package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/griffithind/orbit/internal/secrets"
)

// The secret vault: ciphertext in, ciphertext out.
//
// NOTHING IN THIS FILE DECRYPTS ANYTHING, and that is the boundary worth
// keeping. The store moves sealed bytes; internal/secrets holds the key. A
// function here that took a KEK would put key material one refactor away from a
// query, and the whole property is that database access is not enough.
//
// See migration 0018 and docs/key-custody.md §4.1.

// ErrNoKEK means this deployment has not been initialised with a key encryption
// key. Bootstrap does it; a control plane that finds none cannot open anything
// it has stored.
var ErrNoKEK = errors.New("this deployment has no key encryption key; run `orbitd bootstrap`")

// KEKParams is the salt and verifier a control plane needs to derive and check
// its key encryption key. None of it is secret.
type KEKParams struct {
	Salt               []byte
	VerifierNonce      []byte
	VerifierCiphertext []byte
}

// SealedSecret is one stored key, still sealed.
type SealedSecret struct {
	ID         uuid.UUID
	Kind       secrets.Kind
	Nonce      []byte
	Ciphertext []byte
	NetworkID  *uuid.UUID
}

// InitKEK records this deployment's salt and verifier.
//
// Once, at bootstrap. The INSERT is unconditional rather than an upsert: a
// second call means a second bootstrap against a database that already holds
// secrets, and quietly replacing the salt would make every one of them
// undecryptable while looking like success.
func (t *Tx) InitKEK(ctx context.Context, p KEKParams) error {
	_, err := t.tx.Exec(ctx, `
		INSERT INTO orbit.kek (salt, verifier_nonce, verifier_ciphertext)
		VALUES ($1, $2, $3)`, p.Salt, p.VerifierNonce, p.VerifierCiphertext)
	if err != nil {
		return mapErr(err, "initialise the key encryption key")
	}
	return nil
}

// ReplaceKEKParams swaps the deployment's salt and verifier, for rotation.
//
// An UPDATE of the single row rather than a delete-and-insert, and it must run
// in the SAME transaction that reseals every secret. Splitting them leaves a
// deployment whose stored salt derives a key that opens nothing: the control
// plane would fail its verifier check at startup and refuse to boot, with every
// CA signing key intact and unreachable.
//
// Refuses when no row exists. A deployment with no KEK has not been
// bootstrapped, and rotating nothing into something is InitKEK's job.
func (t *Tx) ReplaceKEKParams(ctx context.Context, p KEKParams) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE orbit.kek SET salt = $1, verifier_nonce = $2, verifier_ciphertext = $3`,
		p.Salt, p.VerifierNonce, p.VerifierCiphertext)
	if err != nil {
		return mapErr(err, "replace the key encryption key")
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("replace the key encryption key: %w", ErrNotFound)
	}
	return nil
}

// GetKEKParams reads the salt and verifier.
func (t *Tx) GetKEKParams(ctx context.Context) (*KEKParams, error) {
	var p KEKParams
	err := t.tx.QueryRow(ctx,
		`SELECT salt, verifier_nonce, verifier_ciphertext FROM orbit.kek`).
		Scan(&p.Salt, &p.VerifierNonce, &p.VerifierCiphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoKEK
	}
	if err != nil {
		return nil, mapErr(err, "read the key encryption key parameters")
	}
	return &p, nil
}

// PutSecret stores a sealed key and returns its ref.
//
// The id is generated BEFORE the seal, by the caller, because it is bound into
// the ciphertext's additional data — the row cannot be moved or relabelled
// without failing to open. That ordering is why this takes an id rather than
// returning one.
func (t *Tx) PutSecret(ctx context.Context, s SealedSecret) error {
	_, err := t.tx.Exec(ctx, `
		INSERT INTO orbit.secret (id, kind, nonce, ciphertext, network_id)
		VALUES ($1, $2, $3, $4, $5)`,
		s.ID, string(s.Kind), s.Nonce, s.Ciphertext, s.NetworkID)
	if err != nil {
		return mapErr(err, "store secret")
	}
	return nil
}

// GetSecret reads a sealed key by id.
func (t *Tx) GetSecret(ctx context.Context, id uuid.UUID) (*SealedSecret, error) {
	var (
		s    SealedSecret
		kind string
	)
	err := t.tx.QueryRow(ctx, `
		SELECT id, kind, nonce, ciphertext, network_id
		  FROM orbit.secret WHERE id = $1`, id).
		Scan(&s.ID, &kind, &s.Nonce, &s.Ciphertext, &s.NetworkID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, mapErr(err, "read secret")
	}
	s.Kind = secrets.Kind(kind)
	return &s, nil
}

// ListSecrets returns every stored key, sealed.
//
// For KEK rotation, which reads them all under the old key and writes them all
// back under the new one. Nothing else should want this: a caller that needs one
// secret knows its id, because the id is in the ref.
func (t *Tx) ListSecrets(ctx context.Context) ([]SealedSecret, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT id, kind, nonce, ciphertext, network_id
		  FROM orbit.secret ORDER BY created_at`)
	if err != nil {
		return nil, mapErr(err, "list secrets")
	}
	defer rows.Close()

	var out []SealedSecret
	for rows.Next() {
		var (
			s    SealedSecret
			kind string
		)
		if err := rows.Scan(&s.ID, &kind, &s.Nonce, &s.Ciphertext, &s.NetworkID); err != nil {
			return nil, mapErr(err, "list secrets")
		}
		s.Kind = secrets.Kind(kind)
		out = append(out, s)
	}
	return out, mapErr(rows.Err(), "list secrets")
}

// ResealSecret replaces a secret's ciphertext, for KEK rotation.
//
// The id and kind do not change, which matters: they are the additional data the
// new ciphertext is bound to, so a reseal that altered either would produce a row
// that cannot be opened by anything.
func (t *Tx) ResealSecret(ctx context.Context, id uuid.UUID, nonce, ciphertext []byte) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE orbit.secret SET nonce = $2, ciphertext = $3 WHERE id = $1`,
		id, nonce, ciphertext)
	if err != nil {
		return mapErr(err, "reseal secret")
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}
