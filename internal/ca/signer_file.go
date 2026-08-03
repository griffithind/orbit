package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/slackhq/nebula/cert"
)

// FileSigner holds a nebula CA signing key on local disk.
//
// This is the supported path for a self-hosted deployment. Be clear-eyed about
// what it means: nebula has no intermediate CAs, so this key is a root of trust
// for the entire mesh. Anyone who reads it can mint a certificate for any
// identity the CA's constraints allow, and the only remedy is a full CA rotation
// across every host.
//
// Three things bound that, and all of them are free:
//
//   - Encryption at rest. A cloud VM's disk snapshots, backups, and a stolen
//     volume are the realistic leak vectors, and an encrypted key survives all
//     three. It does not survive compromise of the running process, which
//     holds the decrypted key in memory.
//   - Permissions. A CA key readable by anyone but its owner is refused at
//     load rather than used, because that mistake is silent otherwise.
//   - A narrow, short-lived CA. Constraints bound what a leaked key can mint;
//     a 90-day lifetime bounds how long it can mint it. Both matter more here
//     than they would with a hardware-backed key.
type FileSigner struct {
	curve cert.Curve

	// mu guards key so Close can zero it while concurrent signs are in flight.
	// Signing is otherwise stateless for both ed25519 and ecdsa.
	mu     sync.RWMutex
	key    []byte
	pub    []byte
	closed bool
}

var _ Signer = (*FileSigner)(nil)

// NewFileSignerFromPEM builds a signer from an unencrypted nebula signing key
// PEM (the format written by `nebula-cert ca -out-key`).
func NewFileSignerFromPEM(pemBytes []byte) (*FileSigner, error) {
	key, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal signing key: %w", err)
	}
	return newFileSigner(curve, key)
}

// NewFileSignerFromEncryptedPEM builds a signer from a passphrase-encrypted
// nebula signing key (`nebula-cert ca -encrypt`).
func NewFileSignerFromEncryptedPEM(passphrase, pemBytes []byte) (*FileSigner, error) {
	curve, key, _, err := cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, pemBytes)
	if err != nil {
		return nil, fmt.Errorf("decrypt signing key: %w", err)
	}
	return newFileSigner(curve, key)
}

// ErrKeyPermissions is returned for a CA key other users can read.
var ErrKeyPermissions = errors.New("ca key is readable by other users")

// ErrPassphraseRequired is returned for an encrypted key with no passphrase.
var ErrPassphraseRequired = errors.New("ca key is encrypted but no passphrase was supplied")

// NewFileSignerFromPath reads a signing key from disk.
//
// Whether the key is encrypted is determined from the PEM banner, not from
// whether a passphrase happened to be supplied. Inferring it from the caller's
// intent produces baffling errors in both directions: a passphrase against a
// plaintext key, or an encrypted key silently failing to parse.
func NewFileSignerFromPath(path string, passphrase []byte) (*FileSigner, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: stat %s: %w", ErrSignerUnavailable, path, err)
	}
	// Refuse rather than warn. A root key that the whole machine can read is a
	// mistake nobody notices, and every other user on that box — including any
	// service that gets popped — can mint mesh identities with it.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s is mode %04o, want 0600 (chmod 600 %s)",
			ErrKeyPermissions, path, mode, path)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrSignerUnavailable, path, err)
	}

	if IsEncryptedKey(b) {
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("%w: set ORBIT_CA_KEY_PASSPHRASE or ORBIT_CA_KEY_PASSPHRASE_FILE", ErrPassphraseRequired)
		}
		return NewFileSignerFromEncryptedPEM(passphrase, b)
	}
	if len(passphrase) > 0 {
		return nil, fmt.Errorf("a passphrase was supplied but %s is not encrypted; "+
			"encrypt it with `orbitd ca encrypt` or unset the passphrase", path)
	}
	return NewFileSignerFromPEM(b)
}

// IsEncryptedKey reports whether a PEM blob holds an encrypted signing key.
func IsEncryptedKey(pemBytes []byte) bool {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return false
	}
	return blk.Type == cert.EncryptedEd25519PrivateKeyBanner ||
		blk.Type == cert.EncryptedECDSAP256PrivateKeyBanner
}

// EncryptKeyFile rewrites a plaintext CA key in encrypted form, in place.
//
// Written to a temp file and renamed, so an interrupted run leaves the original
// intact rather than a truncated key nobody can use.
func EncryptKeyFile(path string, passphrase []byte) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if IsEncryptedKey(b) {
		return nil // idempotent
	}

	raw, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(b)
	if err != nil {
		return fmt.Errorf("parse signing key: %w", err)
	}

	// Argon2 parameters matching nebula-cert's defaults, so a key encrypted
	// here can be decrypted by the stock tooling and vice versa.
	params := cert.NewArgon2Parameters(2*1024*1024, 4, 1)
	enc, err := cert.EncryptAndMarshalSigningPrivateKey(curve, raw, passphrase, params)
	if err != nil {
		return fmt.Errorf("encrypt signing key: %w", err)
	}

	tmp := path + ".new"
	if err := os.WriteFile(tmp, enc, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newFileSigner(curve cert.Curve, key []byte) (*FileSigner, error) {
	pub, err := publicFromSigningKey(curve, key)
	if err != nil {
		return nil, err
	}
	return &FileSigner{curve: curve, key: key, pub: pub}, nil
}

func (s *FileSigner) Curve() cert.Curve { return s.curve }

func (s *FileSigner) Public(_ context.Context) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, fmt.Errorf("%w: signer is closed", ErrSignerUnavailable)
	}
	return bytes.Clone(s.pub), nil
}

func (s *FileSigner) Sign(_ context.Context, certBytes []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, fmt.Errorf("%w: signer is closed", ErrSignerUnavailable)
	}
	return SignBytes(s.curve, s.key, certBytes)
}

// Close zeroes the in-memory key. It does not make the process safe against a
// memory dump taken earlier, it only shortens the window.
func (s *FileSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.key {
		s.key[i] = 0
	}
	s.key = nil
	s.closed = true
	return nil
}

// publicFromSigningKey derives the raw public key bytes that belong in a CA
// certificate, in the encoding nebula's CheckSignature expects.
func publicFromSigningKey(curve cert.Curve, key []byte) ([]byte, error) {
	switch curve {
	case cert.Curve_CURVE25519:
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
		}
		pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
		return bytes.Clone(pub), nil

	case cert.Curve_P256:
		pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
		if err != nil {
			return nil, fmt.Errorf("parse p256 private key: %w", err)
		}
		// Nebula encodes P-256 public keys as the uncompressed ECDH point
		// (0x04 || X || Y). Route through ecdh to get byte-identical output to
		// `nebula-cert ca -curve P256`, which does the same conversion.
		ek, err := pk.ECDH()
		if err != nil {
			return nil, fmt.Errorf("convert p256 key to ecdh: %w", err)
		}
		return ek.PublicKey().Bytes(), nil

	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}
