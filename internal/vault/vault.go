// Package vault joins the two halves of envelope encryption: the store, which
// moves sealed bytes, and internal/secrets, which holds the key.
//
// It exists as its own package because neither half may import the other.
// internal/store must not touch a KEK — a function there that took one would put
// key material one refactor away from a query, and the entire property is that
// database access is not enough. internal/secrets must not import the store, or
// the crypto becomes untestable without Postgres.
//
// So the wiring lives here, and it is the only place in the tree that holds a
// KEK and a database handle at the same time.
package vault

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/secrets"
	"github.com/griffithind/orbit/internal/store"
)

// Vault reads and writes the control plane's private keys.
type Vault struct {
	store *store.Store
	kek   *secrets.KEK
}

// Open derives this deployment's KEK and verifies it before returning.
//
// VERIFIES AT STARTUP, which is the whole reason the verifier columns exist. A
// control plane with a mistyped passphrase that opened cleanly would fail on its
// first signing operation — while somebody was adding a machine, days after the
// mistake, with nothing connecting the two.
func Open(ctx context.Context, st *store.Store) (*Vault, error) {
	pass, err := secrets.Passphrase()
	if err != nil {
		return nil, err
	}

	var params *store.KEKParams
	if err := st.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		params, err = tx.GetKEKParams(ctx)
		return err
	}); err != nil {
		return nil, err
	}

	kek, err := secrets.DeriveKEK(pass, params.Salt)
	if err != nil {
		return nil, err
	}
	if err := kek.CheckVerifier(params.VerifierNonce, params.VerifierCiphertext); err != nil {
		return nil, err
	}
	return &Vault{store: st, kek: kek}, nil
}

// Init records a new deployment's salt and verifier, and returns a usable Vault.
//
// Called once, by bootstrap. A second call fails on the primary key rather than
// replacing the salt — which would leave every already-stored secret
// undecryptable while looking like success.
func Init(ctx context.Context, st *store.Store) (*Vault, error) {
	pass, err := secrets.Passphrase()
	if err != nil {
		return nil, err
	}
	salt, err := secrets.NewSalt()
	if err != nil {
		return nil, err
	}
	kek, err := secrets.DeriveKEK(pass, salt)
	if err != nil {
		return nil, err
	}
	nonce, ct, err := kek.SealVerifier()
	if err != nil {
		return nil, err
	}

	if err := st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.InitKEK(ctx, store.KEKParams{
			Salt: salt, VerifierNonce: nonce, VerifierCiphertext: ct,
		})
	}); err != nil {
		return nil, err
	}
	return &Vault{store: st, kek: kek}, nil
}

// PutTx seals a key and stores it inside the caller's transaction, returning the
// signer ref that names it.
//
// In the CALLER'S transaction deliberately. Bootstrap creates a network, its CA
// and their keys together; a key stored in a transaction that then rolled back
// would be ciphertext nothing references, and a network stored without its key
// would be a network that cannot sign.
func (v *Vault) PutTx(ctx context.Context, tx *store.Tx, kind secrets.Kind, networkID *uuid.UUID, plaintext []byte) (string, error) {
	// The id is generated first because it is bound into the ciphertext's
	// additional data — the row cannot later be moved or relabelled without
	// failing to open.
	id := uuid.New()
	nonce, ct, err := v.kek.Seal(id.String(), kind, plaintext)
	if err != nil {
		return "", err
	}
	if err := tx.PutSecret(ctx, store.SealedSecret{
		ID: id, Kind: kind, Nonce: nonce, Ciphertext: ct, NetworkID: networkID,
	}); err != nil {
		return "", err
	}
	return secrets.Ref(id), nil
}

// get opens a stored secret by ref.
func (v *Vault) get(ctx context.Context, ref string, want secrets.Kind) ([]byte, error) {
	id, err := secrets.ParseRef(ref)
	if err != nil {
		return nil, err
	}

	var sealed *store.SealedSecret
	if err := v.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		sealed, err = tx.GetSecret(ctx, id)
		return err
	}); err != nil {
		return nil, err
	}
	if sealed.Kind != want {
		// Caught here as well as by the AEAD, because this message names both
		// kinds and the AEAD's cannot.
		return nil, fmt.Errorf("secret %s is a %s, not a %s", id, sealed.Kind, want)
	}
	return v.kek.Open(id.String(), sealed.Kind, sealed.Nonce, sealed.Ciphertext)
}

// SignerFactory resolves `db://` refs into CA signers.
//
// The only factory there is. `file://` was removed rather than deprecated: two
// custody paths meant two sets of failure modes, two things to document, and a
// second replica that worked or did not depending on which one a network
// happened to use. See docs/key-custody.md.
// Rotate re-seals every stored secret under a key derived from a new
// passphrase, and replaces the deployment's salt and verifier.
//
// ONE TRANSACTION, and that is the whole design. A partial rotation is the worst
// outcome available here: secrets sealed under two different keys, a stored salt
// that opens some of them, and a control plane that fails its verifier check and
// will not start — with every CA signing key present and unreadable. Postgres
// either takes all of it or none.
//
// Each secret is opened with the old key and sealed with the new one under the
// same id and kind, so the additional data that binds a ciphertext to its row is
// unchanged and a rotated secret is still refused if it is later moved or
// relabelled.
//
// Returns how many secrets were resealed. Zero is a legitimate answer for a
// deployment that has bootstrapped and not yet created a network.
func (v *Vault) Rotate(ctx context.Context, newPassphrase []byte) (int, error) {
	salt, err := secrets.NewSalt()
	if err != nil {
		return 0, err
	}
	next, err := secrets.DeriveKEK(newPassphrase, salt)
	if err != nil {
		return 0, err
	}
	vn, vc, err := next.SealVerifier()
	if err != nil {
		return 0, err
	}

	var resealed int
	err = v.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		sealed, err := tx.ListSecrets(ctx)
		if err != nil {
			return err
		}
		for _, s := range sealed {
			plain, err := v.kek.Open(s.ID.String(), s.Kind, s.Nonce, s.Ciphertext)
			if err != nil {
				// The old key does not open a row it is supposed to own. Stop:
				// continuing would commit a mixture, and a mixture cannot be
				// unpicked without the key that is evidently missing.
				return fmt.Errorf("open secret %s (%s) with the current key: %w", s.ID, s.Kind, err)
			}
			nonce, ct, err := next.Seal(s.ID.String(), s.Kind, plain)
			if err != nil {
				return err
			}
			if err := tx.ResealSecret(ctx, s.ID, nonce, ct); err != nil {
				return err
			}
			resealed++
		}
		return tx.ReplaceKEKParams(ctx, store.KEKParams{
			Salt: salt, VerifierNonce: vn, VerifierCiphertext: vc,
		})
	})
	if err != nil {
		return 0, err
	}

	v.kek = next
	return resealed, nil
}

// DeriveKey returns a deployment-wide subkey for a named purpose.
//
// The point is that every replica gets the same bytes without them being stored:
// all replicas derive the KEK from the same passphrase and the same salt, so
// anything derived from it agrees across processes by construction.
func (v *Vault) DeriveKey(label string, n int) ([]byte, error) {
	return v.kek.Derive(label, n)
}

func (v *Vault) SignerFactory() ca.SignerFactory {
	return func(ctx context.Context, ref string) (ca.Signer, error) {
		if !secrets.IsRef(ref) {
			return nil, fmt.Errorf("%q is not a vault reference; keys are stored in the "+
				"database and `file://` is no longer supported", ref)
		}
		pem, err := v.get(ctx, ref, secrets.KindCASigning)
		if err != nil {
			return nil, err
		}
		// The stored plaintext is the same PEM a file:// signer reads, so both
		// paths converge on one parser. Storing a different encoding for the
		// vault would have meant two, and a bug in either would look like a
		// corrupt key.
		return ca.NewPEMSigner(pem)
	}
}

// NetworkIdentity resolves a signer ref into a network identity private key.
func (v *Vault) NetworkIdentity(ctx context.Context, ref string) (ed25519.PrivateKey, error) {
	pem, err := v.get(ctx, ref, secrets.KindNetworkIdentity)
	if err != nil {
		return nil, err
	}
	return ca.ParseNetworkIdentityPEM(pem)
}
