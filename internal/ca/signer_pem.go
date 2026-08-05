package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"sync"

	"github.com/slackhq/nebula/cert"
)

// PEMSigner is a CA signer built from a PEM-encoded key already in memory.
//
// It reads no files and knows nothing about custody. The key reaches it having
// been decrypted by the vault (internal/secrets), which is the only place a
// private key is stored — the file-backed variants that used to live here, with
// their own mode checks and passphrase handling, went with them.
//
// What it still is: a root of trust for the entire mesh while it exists. Nebula
// has no intermediate CAs, so anyone who obtains this key can mint a certificate
// for any identity the CA's constraints allow, and the only remedy is a full CA
// rotation across every host. Close() zeroes it.

type PEMSigner struct {
	curve cert.Curve

	// mu guards key so Close can zero it while concurrent signs are in flight.
	// Signing is otherwise stateless for both ed25519 and ecdsa.
	mu     sync.RWMutex
	key    []byte
	pub    []byte
	closed bool
}

var _ Signer = (*PEMSigner)(nil)

// NewPEMSigner builds a signer from an unencrypted nebula signing key
// PEM (the format written by `nebula-cert ca -out-key`).
func NewPEMSigner(pemBytes []byte) (*PEMSigner, error) {
	key, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal signing key: %w", err)
	}
	return newPEMSigner(curve, key)
}

func newPEMSigner(curve cert.Curve, key []byte) (*PEMSigner, error) {
	pub, err := publicFromSigningKey(curve, key)
	if err != nil {
		return nil, err
	}
	return &PEMSigner{curve: curve, key: key, pub: pub}, nil
}

func (s *PEMSigner) Curve() cert.Curve { return s.curve }

func (s *PEMSigner) Public(_ context.Context) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, fmt.Errorf("%w: signer is closed", ErrSignerUnavailable)
	}
	return bytes.Clone(s.pub), nil
}

func (s *PEMSigner) Sign(_ context.Context, certBytes []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, fmt.Errorf("%w: signer is closed", ErrSignerUnavailable)
	}
	return SignBytes(s.curve, s.key, certBytes)
}

// Close zeroes the in-memory key. It does not make the process safe against a
// memory dump taken earlier, it only shortens the window.
func (s *PEMSigner) Close() error {
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

// SignDigest lets a file-backed key sign an already-hashed message, which is
// what X.509 issuance needs. See SignDigestBytes for why only P-256 can.
func (s *PEMSigner) SignDigest(_ context.Context, digest []byte, hash crypto.Hash) ([]byte, error) {
	// Under the read lock, like Sign: Close zeroes the key, and a signature over
	// a half-zeroed key would verify against nothing and look like corruption.
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, errors.New("signer is closed")
	}
	return SignDigestBytes(s.curve, s.key, digest, hash)
}
