package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// APITokenPrefix marks Orbit admin tokens so secret scanners can match them and
// so a leaked string is identifiable at a glance.
const APITokenPrefix = "orbat_"

// NewAPIToken generates a token and returns the plaintext plus its stored hash.
//
// 32 random bytes is 256 bits, so a fast hash is the right choice for the
// stored form: there is nothing for an attacker to brute force. Unlike
// enrollment credentials these are long-lived, so they are not peppered, and a
// database leak does not yield usable tokens because SHA-256 is preimage
// resistant against a value this large.
func NewAPIToken() (plaintext string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	plaintext = APITokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))
	return plaintext, sum[:], nil
}

// CreateAPIToken stores a token. The caller keeps the plaintext, which exists
// only in the response that created it.
func (t *Tx) CreateAPIToken(ctx context.Context, name string, hash []byte, scopes []string, expiresAt *time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := t.tx.QueryRow(ctx, `
		INSERT INTO orbit.api_token (name, token_hash, scopes, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id`,
		name, hash, nonNil(scopes), expiresAt,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, mapErr(err, "create api token")
	}
	return id, nil
}

// APIToken is a token's metadata. It deliberately has no field for the hash:
// nothing outside this file needs it, and a struct that carries it is a struct
// that eventually gets logged or serialized.
type APIToken struct {
	ID         uuid.UUID
	Name       string
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// ListAPITokens returns every token, revoked ones included.
//
// Revoked tokens are listed rather than hidden because "was this token ever
// used after we revoked it" is the question an incident asks, and last_used_at
// answers it only if the row is visible.
func (t *Tx) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := t.tx.Query(ctx, `
		SELECT id, name, scopes, created_at, expires_at, last_used_at, revoked_at
		  FROM orbit.api_token
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, mapErr(err, "list api tokens")
	}
	defer rows.Close()

	var out []APIToken
	for rows.Next() {
		var tok APIToken
		if err := rows.Scan(&tok.ID, &tok.Name, &tok.Scopes,
			&tok.CreatedAt, &tok.ExpiresAt, &tok.LastUsedAt, &tok.RevokedAt); err != nil {
			return nil, mapErr(err, "scan api token")
		}
		out = append(out, tok)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks a token unusable.
//
// Revocation takes effect on the next request with no propagation delay and no
// cache to invalidate, because AuthenticateToken filters on revoked_at in the
// same query that resolves the token. That is the whole reason authentication
// hits the database on every request rather than caching identities.
//
// Revoking an already-revoked token returns ErrNotFound: the WHERE clause
// excludes it. That makes a double-revoke visible rather than silently
// successful, which matters when an operator is working through a leak and
// needs to know whether they are the one who revoked it.
func (t *Tx) RevokeAPIToken(ctx context.Context, id uuid.UUID) error {
	tag, err := t.tx.Exec(ctx, `
		UPDATE orbit.api_token
		   SET revoked_at = now()
		 WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return mapErr(err, "revoke api token")
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("revoke api token: %w", ErrNotFound)
	}
	return nil
}
