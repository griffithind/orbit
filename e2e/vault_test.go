package e2e

import (
	"context"
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

	if _, err := conn.Exec(ctx, "TRUNCATE orbit.secret, orbit.kek"); err != nil {
		t.Fatalf("reset the vault: %v", err)
	}
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
