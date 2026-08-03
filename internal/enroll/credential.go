// Package enroll implements host enrollment: minting enrollment credentials,
// redeeming them, and issuing the first certificate.
package enroll

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// Credential format: orb_<version>_<base32 of 24 random bytes>.
//
// 24 bytes is 192 bits of entropy, which is why the stored form can be a fast
// keyed hash rather than a slow KDF. An earlier draft of the design specified
// Argon2id on the theory that enrollment codes are low-entropy secrets; that is
// true of human-chosen or human-typed codes and false of these. Argon2id's cost
// buys nothing against a 192-bit random value, and it would have forced either
// a random salt (making lookup-by-hash impossible) or a fixed salt (which is
// just a slow keyed hash with extra steps).
//
// What the stored form does need is to be useless on its own after a database
// leak, and to be deterministic so a single indexed lookup can find it. HMAC
// with a server-side pepper gives both: an attacker holding the table cannot
// derive a usable code without the pepper, and Hash() of the same code always
// produces the same bytes.
const (
	prefix         = "orb"
	formatVersion  = "1"
	secretBytes    = 24
	minPepperBytes = 32
)

var (
	ErrMalformed      = errors.New("malformed enrollment credential")
	ErrPepperTooShort = fmt.Errorf("pepper must be at least %d bytes", minPepperBytes)
)

// encoding is unpadded base32 without ambiguous characters in the alphabet's
// visual space. Base32 rather than base64 so a code survives being read aloud,
// written down, or passed through a system that mangles case-sensitive text.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Hasher converts a plaintext credential into its stored form.
//
// The pepper must be identical across every control-plane replica, and must not
// be stored in the same place as the database. Losing it invalidates every
// outstanding credential, which given a 15-minute TTL is a minor operational
// event rather than a data-loss one; that short blast radius is what makes
// pepper rotation cheap enough to actually do.
type Hasher struct {
	pepper []byte
}

// NewHasher validates and retains the pepper.
func NewHasher(pepper []byte) (*Hasher, error) {
	if len(pepper) < minPepperBytes {
		return nil, ErrPepperTooShort
	}
	return &Hasher{pepper: pepper}, nil
}

// Hash returns the stored form of a credential.
func (h *Hasher) Hash(credential string) []byte {
	mac := hmac.New(sha256.New, h.pepper)
	mac.Write([]byte(credential))
	return mac.Sum(nil)
}

// NewCredential mints a fresh credential and returns the plaintext alongside
// its stored form.
//
// The plaintext is returned exactly once and must never be persisted. It exists
// only long enough to reach the HTTP response that created it.
func (h *Hasher) NewCredential() (plaintext string, stored []byte, err error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate credential: %w", err)
	}
	plaintext = fmt.Sprintf("%s_%s_%s", prefix, formatVersion, encoding.EncodeToString(raw))
	return plaintext, h.Hash(plaintext), nil
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
