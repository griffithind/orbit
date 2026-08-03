package ca

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/slackhq/nebula/cert"
)

// GenerateCAKey creates a nebula CA *signing* keypair and returns
// (publicKey, rawPrivateKey) in the encodings nebula expects.
//
// Nebula uses different key types for the two roles, and mixing them up is a
// common and confusing mistake:
//
//	CA / signing key    Curve_CURVE25519 -> Ed25519   (signature)
//	                    Curve_P256       -> ECDSA P-256
//	Host / static key   Curve_CURVE25519 -> X25519    (Diffie-Hellman)
//	                    Curve_P256       -> ECDH P-256
//
// A host's static key therefore cannot produce signatures on the 25519 curve.
// Do not design agent authentication around signing with the host key; see
// docs/enrollment.md.
//
// This function generates key material in the control plane's address space.
// That is acceptable for development, tests, and single-operator deployments,
// but a production CA key should be generated inside the KMS or HSM and only
// ever referenced through a RemoteSigner.
func GenerateCAKey(curve cert.Curve) (pub, rawPriv []byte, err error) {
	switch curve {
	case cert.Curve_CURVE25519:
		pub, rawPriv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		return pub, rawPriv, nil

	case cert.Curve_P256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ecdsa p256 key: %w", err)
		}
		// nebula-cert takes the same detour through ecdh purely to reach the
		// raw byte encodings; we match it so keys are interchangeable.
		ek, err := key.ECDH()
		if err != nil {
			return nil, nil, fmt.Errorf("convert ecdsa key to ecdh: %w", err)
		}
		return ek.PublicKey().Bytes(), ek.Bytes(), nil

	default:
		return nil, nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// GenerateHostKey creates a nebula host *static* keypair (the Noise DH key).
//
// This is included for tests and for the agent's reference implementation. In
// production the agent generates this on the host and transmits only the public
// half; the control plane must never see or store a host private key.
func GenerateHostKey(curve cert.Curve) (pub, rawPriv []byte, err error) {
	switch curve {
	case cert.Curve_CURVE25519:
		priv := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, priv); err != nil {
			return nil, nil, fmt.Errorf("read random bytes: %w", err)
		}
		key, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("derive x25519 key: %w", err)
		}
		return key.PublicKey().Bytes(), priv, nil

	case cert.Curve_P256:
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ecdh p256 key: %w", err)
		}
		return key.PublicKey().Bytes(), key.Bytes(), nil

	default:
		return nil, nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// memorySigner is a Signer backed by raw key bytes held in memory. It is the
// development and test implementation; FileSigner wraps the same logic with PEM
// loading, and KMSSigner replaces it entirely in production.
type memorySigner struct {
	curve cert.Curve
	pub   []byte
	priv  []byte
}

var _ Signer = (*memorySigner)(nil)

// NewMemorySigner builds a Signer from raw key bytes.
//
// Exported for tests and for `orbit ca create --dev`. Every call site should be
// obviously non-production.
func NewMemorySigner(curve cert.Curve, pub, priv []byte) Signer {
	return &memorySigner{curve: curve, pub: pub, priv: priv}
}

func (s *memorySigner) Curve() cert.Curve { return s.curve }

func (s *memorySigner) Public(_ context.Context) ([]byte, error) { return s.pub, nil }

func (s *memorySigner) Sign(_ context.Context, certBytes []byte) ([]byte, error) {
	return SignBytes(s.curve, s.priv, certBytes)
}

func (s *memorySigner) Close() error { return nil }

// PublicFromHostKey derives the public half of a host static key.
//
// Used when renewing with --reuse-key, where the private key must stay put (a
// hardware-backed key cannot be regenerated) but the control plane still needs
// the public half to mint a certificate.
func PublicFromHostKey(curve cert.Curve, priv []byte) ([]byte, error) {
	switch curve {
	case cert.Curve_CURVE25519:
		key, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("derive x25519 public key: %w", err)
		}
		return key.PublicKey().Bytes(), nil

	case cert.Curve_P256:
		key, err := ecdh.P256().NewPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("derive p256 public key: %w", err)
		}
		return key.PublicKey().Bytes(), nil

	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// SharedSecret performs Diffie-Hellman between a private key and a peer's
// public key.
//
// Used by the recovery flow to prove possession of a host key without a
// signature. Nebula host keys on Curve25519 are X25519 — key agreement only,
// no signing operation — so a signed-nonce challenge is not available and an
// ECDH challenge is what remains.
func SharedSecret(curve cert.Curve, priv, peerPub []byte) ([]byte, error) {
	switch curve {
	case cert.Curve_CURVE25519:
		k, err := ecdh.X25519().NewPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("parse x25519 private key: %w", err)
		}
		p, err := ecdh.X25519().NewPublicKey(peerPub)
		if err != nil {
			return nil, fmt.Errorf("parse x25519 public key: %w", err)
		}
		return k.ECDH(p)

	case cert.Curve_P256:
		k, err := ecdh.P256().NewPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("parse p256 private key: %w", err)
		}
		p, err := ecdh.P256().NewPublicKey(peerPub)
		if err != nil {
			return nil, fmt.Errorf("parse p256 public key: %w", err)
		}
		return k.ECDH(p)

	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

// DeriveHostKey turns 32 bytes of key material into a usable host private key.
//
// Returns an error for a scalar the curve rejects, which the caller handles by
// deriving again with a different counter. Vanishingly unlikely on P-256 and
// impossible on X25519 (every 32-byte string is a valid clamped scalar), but a
// silent failure here would be a broken challenge nobody could debug.
func DeriveHostKey(curve cert.Curve, material []byte) (priv, pub []byte, err error) {
	switch curve {
	case cert.Curve_CURVE25519:
		k, err := ecdh.X25519().NewPrivateKey(material)
		if err != nil {
			return nil, nil, err
		}
		return k.Bytes(), k.PublicKey().Bytes(), nil

	case cert.Curve_P256:
		k, err := ecdh.P256().NewPrivateKey(material)
		if err != nil {
			return nil, nil, err
		}
		return k.Bytes(), k.PublicKey().Bytes(), nil

	default:
		return nil, nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}
