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
