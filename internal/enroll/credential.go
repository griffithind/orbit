// Package enroll implements host enrollment: minting enrollment credentials,
// redeeming them, and issuing the first certificate.
package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// Credential format: orb_<version>_<base32 of 24 random bytes>.
//
// 24 bytes is 192 bits of entropy, and that single fact decides everything else
// about how these are stored.
//
// NO SLOW KDF. An early draft specified Argon2id on the theory that enrollment
// codes are low-entropy secrets. That is true of human-chosen codes and false of
// these: Argon2id's cost buys nothing against a 192-bit random value, and it
// would have forced either a random salt (making lookup-by-hash impossible) or a
// fixed salt, which is a slow keyed hash with extra steps.
//
// NO PEPPER EITHER, and that took longer to see. The stored form was an HMAC
// under a server-side pepper, justified as "an attacker holding the table cannot
// derive a usable code without it". Against 192 bits of CSPRNG output, plain
// SHA-256 is exactly as underivable — there is no precomputation to frustrate,
// no dictionary to widen, and no guess to slow down. The pepper stopped nothing
// the entropy had not already stopped.
//
// What it cost was real: a per-deployment secret that had to be byte-identical
// on every control-plane replica and stored apart from the database, which made
// it one of the things blocking a second replica from working at all. See
// docs/key-custody.md §4.3.
//
// So the stored form is SHA-256 of the plaintext. It keeps the two properties
// that were ever needed — useless on its own after a database leak, and
// deterministic, so redemption is one indexed lookup.
const (
	prefix        = "orb"
	formatVersion = "1"
	secretBytes   = 24
)

var ErrMalformed = errors.New("malformed enrollment credential")

// encoding is unpadded base32 without ambiguous characters in the alphabet's
// visual space. Base32 rather than base64 so a code survives being read aloud,
// written down, or passed through a system that mangles case-sensitive text.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Hash returns the stored form of a credential.
//
// A plain digest, holding no state and needing no configuration. That is the
// whole point of the change recorded above: there is nothing here for an
// operator to distribute, keep in step across replicas, or lose.
func Hash(credential string) []byte {
	sum := sha256.Sum256([]byte(credential))
	return sum[:]
}

// NewCredential mints a fresh credential and returns the plaintext alongside
// its stored form.
//
// The plaintext is returned exactly once and must never be persisted. It exists
// only long enough to reach the HTTP response that created it.
func NewCredential() (plaintext string, stored []byte, err error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate credential: %w", err)
	}
	plaintext = fmt.Sprintf("%s_%s_%s", prefix, formatVersion, encoding.EncodeToString(raw))
	return plaintext, Hash(plaintext), nil
}

// Validate checks a credential's shape before it reaches the database.
//
// This is a cheap filter, not a security control: it lets an obviously bogus
// value be rejected without a query, and lets a client catch a transcription
// error before making a request. A well-formed credential is still just as
// unauthenticated until redemption succeeds.
func Validate(credential string) error {
	parts := strings.Split(credential, "_")
	if len(parts) != 3 {
		return ErrMalformed
	}
	if parts[0] != prefix || parts[1] != formatVersion {
		return ErrMalformed
	}
	raw, err := encoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(raw) != secretBytes {
		return ErrMalformed
	}
	return nil
}
