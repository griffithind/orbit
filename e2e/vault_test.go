package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/secrets"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/vault"
)

// The key vault, against real Postgres.
//
// What these assert is the property the whole design rests on: the ciphertext is
// in the database and the key is not, so database access alone is not enough to
// mint a certificate. See docs/key-custody.md §4.1.

// withPassphrase sets the KEK passphrase for one test.
func withPassphrase(t *testing.T, s string) {
	t.Helper()
	t.Setenv("ORBIT_KEK_PASSPHRASE", s)
}

// resetVault empties the KEK and every secret, as the SUPERUSER.
//
// The KEK is deployment-wide by design — one row, enforced by a constant primary
// key — and every test in this package shares one database, so without this the
// second test to call vault.Init collides with the first. Each case here is
// standing up a notionally separate deployment.
//
// It connects as the admin role deliberately. orbit_app cannot delete the kek
// row, which is the point of migration 0018's REVOKE; a fixture that could would
// mean the application could too. Reaching around it with the superuser is what a
// superuser is for, and it keeps the restriction real everywhere else.
func resetVault(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn("ORBIT_TEST_DSN", adminDSN))
	if err != nil {
		t.Fatalf("connect as admin: %v", err)
	}
	defer conn.Close(ctx)

	truncate := func() {
		if _, err := conn.Exec(ctx, "TRUNCATE orbit.secret, orbit.kek"); err != nil {
			t.Fatalf("reset the vault: %v", err)
		}
	}
	truncate()

	// And again on the way out. These cases deliberately re-key the deployment
	// with passphrases of their own, and the KEK is deployment-wide — so without
	// this, every harness built AFTER a vault test would find a KEK it cannot
	// open and fail with ErrWrongKEK, in a test that has nothing to do with
	// custody. Leaving no KEK at all is the one state setup() can always
	// recover from: it initialises a fresh one.
	t.Cleanup(func() {
		conn, err := pgx.Connect(context.Background(), dsn("ORBIT_TEST_DSN", adminDSN))
		if err != nil {
			t.Fatalf("connect as admin: %v", err)
		}
		defer conn.Close(context.Background())
		if _, err := conn.Exec(context.Background(), "TRUNCATE orbit.secret, orbit.kek"); err != nil {
			t.Fatalf("reset the vault: %v", err)
		}
	})
}

func TestVaultRoundTripsAKey(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	resetVault(t)
	withPassphrase(t, "the deployment passphrase")

	v, err := vault.Init(ctx, h.store)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	_, priv, err := ca.GenerateNetworkIdentity()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := ca.MarshalNetworkIdentityPEM(priv)

	var ref string
	if err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		ref, err = v.PutTx(ctx, tx, secrets.KindNetworkIdentity, nil, plaintext)
		return err
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if !secrets.IsRef(ref) {
		t.Fatalf("ref %q does not name the vault", ref)
	}

	got, err := v.NetworkIdentity(ctx, ref)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Equal(priv) {
		t.Fatal("the key that came back is not the key that went in")
	}
}

// TestTheDatabaseAloneIsNotEnough is the point of the whole exercise.
//
// An attacker with a pg_dump, a read replica, or an SQL-injection bug holds
// every byte this test holds. Without the passphrase — which lives on the
// control-plane host and never reaches Postgres — none of it opens.
func TestTheDatabaseAloneIsNotEnough(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	resetVault(t)

	withPassphrase(t, "the real one")
	v, err := vault.Init(ctx, h.store)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	_, priv, _ := ca.GenerateNetworkIdentity()
	var ref string
	if err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		ref, err = v.PutTx(ctx, tx, secrets.KindNetworkIdentity, nil, ca.MarshalNetworkIdentityPEM(priv))
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Everything an attacker with database read access has.
	id, err := secrets.ParseRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	var sealed *store.SealedSecret
	if err := h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		sealed, err = tx.GetSecret(ctx, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(sealed.Ciphertext) == 0 {
		t.Fatal("nothing was stored")
	}
	// The key must not be recoverable from what the database holds.
	if _, err := ca.ParseNetworkIdentityPEM(sealed.Ciphertext); err == nil {
		t.Fatal("the stored bytes parse as a private key; they are not encrypted")
	}

	// And a wrong passphrase does not open it.
	withPassphrase(t, "a guess")
	if _, err := vault.Open(ctx, h.store); !errors.Is(err, secrets.ErrWrongKEK) {
		t.Fatalf("opening with the wrong passphrase gave %v, want ErrWrongKEK", err)
	}
}

// TestWrongPassphraseFailsAtStartup.
//
// WHERE it fails is the point. A replica that started cleanly and failed on its
// first signing operation would fail while somebody was adding a machine, days
// after the passphrase was mistyped, with nothing connecting the two.
func TestWrongPassphraseFailsAtStartup(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	resetVault(t)

	withPassphrase(t, "correct")
	if _, err := vault.Init(ctx, h.store); err != nil {
		t.Fatalf("init: %v", err)
	}

	withPassphrase(t, "incorrect")
	_, err := vault.Open(ctx, h.store)
	if !errors.Is(err, secrets.ErrWrongKEK) {
		t.Fatalf("error = %v, want ErrWrongKEK", err)
	}

	withPassphrase(t, "correct")
	if _, err := vault.Open(ctx, h.store); err != nil {
		t.Fatalf("the right passphrase was refused: %v", err)
	}
}

// TestNoPassphraseIsDistinctFromWrongPassphrase.
//
// Two different operator mistakes with two different fixes: one is "set the
// variable", the other is "you set the wrong value". A single error would send
// half the readers down the wrong path.
func TestNoPassphraseIsDistinctFromWrongPassphrase(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	resetVault(t)

	withPassphrase(t, "something")
	if _, err := vault.Init(ctx, h.store); err != nil {
		t.Fatal(err)
	}

	os.Unsetenv("ORBIT_KEK_PASSPHRASE")
	t.Setenv("ORBIT_CA_KEY_PASSPHRASE", "")
	_, err := vault.Open(ctx, h.store)
	if !errors.Is(err, secrets.ErrNoKEK) {
		t.Fatalf("error with no passphrase = %v, want ErrNoKEK", err)
	}
}

// TestNoVaultIsNotAnError.
//
// A deployment whose keys are all on disk has no KEK row, and must start
// normally — that path is the single-VM one and it worked before any of this
// existed.
func TestNoVaultIsNotAnError(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	resetVault(t)
	withPassphrase(t, "irrelevant")

	_, err := vault.Open(ctx, h.store)
	if !errors.Is(err, store.ErrNoKEK) {
		t.Fatalf("error = %v, want store.ErrNoKEK so orbitd can carry on with file keys", err)
	}
}

// TestRotationRekeysEverySecret.
//
// docs/key-custody.md said the KEK "rotates, by resealing every secret". The
// primitives existed — Tx.ListSecrets and Tx.ResealSecret, each documented as
// being for exactly this — and nothing called either, which the reachability
// gate could not see because they are exported methods on a type that is
// instantiated everywhere.
//
// The property is narrow and total: after rotating, every stored key opens under
// the NEW passphrase and none opens under the old one. Half of that is not a
// weaker version of the whole — a deployment whose secrets are split across two
// keys has no working passphrase at all.
func TestRotationRekeysEverySecret(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	resetVault(t)
	withPassphrase(t, "the original passphrase")

	v, err := vault.Init(ctx, h.store)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	// More than one, and of the kind the deployment actually stores, so this
	// exercises the loop rather than a single row.
	refs := map[string]ed25519.PrivateKey{}
	for range 3 {
		_, priv, err := ca.GenerateNetworkIdentity()
		if err != nil {
			t.Fatal(err)
		}
		var ref string
		if err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			var err error
			ref, err = v.PutTx(ctx, tx, secrets.KindNetworkIdentity, nil,
				ca.MarshalNetworkIdentityPEM(priv))
			return err
		}); err != nil {
			t.Fatalf("put: %v", err)
		}
		refs[ref] = priv
	}

	n, err := v.Rotate(ctx, []byte("the new passphrase"))
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n != len(refs) {
		t.Errorf("re-sealed %d secrets, expected %d", n, len(refs))
	}

	// A fresh process, holding only the new passphrase, opens everything.
	withPassphrase(t, "the new passphrase")
	after, err := vault.Open(ctx, h.store)
	if err != nil {
		t.Fatalf("open with the new passphrase: %v", err)
	}
	for ref, want := range refs {
		got, err := after.NetworkIdentity(ctx, ref)
		if err != nil {
			t.Fatalf("read %s after rotation: %v", ref, err)
		}
		if !got.Equal(want) {
			t.Errorf("%s came back as a different key", ref)
		}
	}

	// And the old passphrase is genuinely retired. If this still opened, the
	// rotation would have added a key rather than replaced one.
	withPassphrase(t, "the original passphrase")
	if _, err := vault.Open(ctx, h.store); err == nil {
		t.Error("the old passphrase still opens the vault after rotation")
	}
}

// TestAFailedRotationChangesNothing.
//
// The reason Rotate is one transaction. A partial rotation is the worst outcome
// available: secrets under two different keys, a stored salt that opens only
// some of them, and a control plane that fails its verifier check and will not
// start — with every CA signing key present and unreadable.
//
// Driven by corrupting one row so the old key cannot open it, which is what a
// bit-flip or a restore of mismatched backups would look like. The rotation must
// abort with the deployment exactly as it was.
func TestAFailedRotationChangesNothing(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	resetVault(t)
	withPassphrase(t, "before any rotation")

	v, err := vault.Init(ctx, h.store)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	_, priv, err := ca.GenerateNetworkIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var good string
	if err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		good, err = v.PutTx(ctx, tx, secrets.KindNetworkIdentity, nil,
			ca.MarshalNetworkIdentityPEM(priv))
		return err
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// A second row the old key cannot open.
	conn, err := pgx.Connect(ctx, dsn("ORBIT_TEST_DSN", adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `
		INSERT INTO orbit.secret (kind, nonce, ciphertext)
		VALUES ('network_identity_key', $1, $2)`,
		make([]byte, 24), bytes.Repeat([]byte{0xff}, 48)); err != nil {
		t.Fatalf("plant a corrupt secret: %v", err)
	}

	if _, err := v.Rotate(ctx, []byte("a passphrase that must not take effect")); err == nil {
		t.Fatal("rotation reported success despite a secret it could not open")
	}

	// Nothing moved: the original passphrase still opens the vault, and the key
	// that was readable before is readable now.
	withPassphrase(t, "before any rotation")
	again, err := vault.Open(ctx, h.store)
	if err != nil {
		t.Fatalf("the original passphrase no longer opens the vault: %v", err)
	}
	got, err := again.NetworkIdentity(ctx, good)
	if err != nil {
		t.Fatalf("read a key that was fine before the failed rotation: %v", err)
	}
	if !got.Equal(priv) {
		t.Error("the key changed under a rotation that failed")
	}

	// And the passphrase the failed rotation was heading for must not work.
	withPassphrase(t, "a passphrase that must not take effect")
	if _, err := vault.Open(ctx, h.store); err == nil {
		t.Error("the new passphrase opens the vault after a rotation that failed")
	}
}
