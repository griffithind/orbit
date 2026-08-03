// Package ca implements Orbit's certificate authority service.
//
// Nebula has no intermediate CAs: cert.CAPool.AddCA rejects anything that is
// not self-signed, and TBSCertificate.SignWith refuses to sign a cert with
// IsCA set. Verification is a single map lookup by issuer fingerprint, not a
// chain walk. That means the key Orbit signs with is a *root* key that every
// node in the mesh trusts directly.
//
// Two things follow, and they drive the design of this package:
//
//  1. The private key must never be recoverable from the control plane. All
//     signing goes through the Signer interface, which is an adapter onto
//     nebula's cert.SignerLambda. The default deployment binds it to a cloud
//     KMS or a PKCS#11 token; raw key bytes are a development affordance only.
//
//  2. Blast radius must be bounded by the CA itself. Nebula enforces CA
//     constraints on every signature (cert/ca_pool.go checkCAConstraints) and
//     on every verification, so a CA scoped to one prefix, one group set, and
//     a short validity window cannot mint anything outside that box even if
//     the signing path is fully compromised. Orbit issues narrow CAs by
//     default rather than one CA per organization.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/slackhq/nebula/cert"
)

var (
	// ErrCurveMismatch is returned when a signer's curve does not match the
	// certificate being signed. Nebula rejects a CA and leaf with different
	// curves at verification time (ErrCurveMismatch in cert/ca_pool.go), so we
	// catch it at issuance instead of shipping a cert that can never verify.
	ErrCurveMismatch = errors.New("signer curve does not match certificate curve")

	// ErrSignerUnavailable indicates the backing key material could not be
	// reached. Callers must treat this as retryable and must not fall back to
	// any other signer: silently signing with a different CA would issue a
	// certificate the mesh does not trust.
	ErrSignerUnavailable = errors.New("signer unavailable")
)

// Signer produces nebula certificate signatures without exposing private key
// material to the caller.
//
// Implementations must be safe for concurrent use: the issuer holds a single
// Signer for the lifetime of a CA and signs from many request goroutines.
//
// Sign receives the exact bytes nebula wants signed (the output of
// marshalForSigning) and must return a signature in the form nebula's
// CheckSignature expects for the curve:
//
//	Curve_CURVE25519 -> raw Ed25519 signature over certBytes
//	Curve_P256       -> ASN.1 ECDSA signature over SHA-256(certBytes)
//
// SignWith normalizes P-256 signatures to low-S afterwards, so implementations
// do not need to.
type Signer interface {
	// Curve reports which nebula curve this signer's key belongs to.
	Curve() cert.Curve

	// Public returns the raw public key bytes, in the same encoding
	// cert.Certificate.PublicKey() uses for this curve.
	Public(ctx context.Context) ([]byte, error)

	// Sign returns a signature over certBytes. It must return an error
	// wrapping ErrSignerUnavailable for transient backend failures so callers
	// can distinguish "retry" from "this will never work".
	Sign(ctx context.Context, certBytes []byte) ([]byte, error)

	// Close releases any backend resources (HSM session, KMS client).
	Close() error
}

// lambda adapts a Signer to nebula's cert.SignerLambda.
//
// cert.SignerLambda has no context and no error context of its own, so we
// capture ctx here and let the error propagate out of SignWith. Any error
// returned by the Signer aborts the signature and surfaces to the caller of
// CreateCA/IssueHost.
func lambda(ctx context.Context, s Signer) cert.SignerLambda {
	return func(certBytes []byte) ([]byte, error) {
		sig, err := s.Sign(ctx, certBytes)
		if err != nil {
			return nil, err
		}
		if len(sig) == 0 {
			// A zero-length signature is accepted by neither setSignature nor
			// CheckSignature, but failing here gives a far better error than
			// "invalid certificate" three frames up.
			return nil, errors.New("signer returned an empty signature")
		}
		return sig, nil
	}
}

// SignBytes performs the raw signing operation for a locally held private key.
// It exists so in-process signers (file, memory, and test doubles) all agree on
// the wire format, and so that a KMS implementation has a reference to match.
//
// This mirrors the switch inside cert.TBSCertificate.Sign; it is duplicated
// rather than reused because that function only accepts raw key bytes, which is
// exactly what a Signer is supposed to avoid handling.
func SignBytes(curve cert.Curve, key []byte, certBytes []byte) ([]byte, error) {
	switch curve {
	case cert.Curve_CURVE25519:
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
		}
		return ed25519.Sign(ed25519.PrivateKey(key), certBytes), nil

	case cert.Curve_P256:
		pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
		if err != nil {
			return nil, fmt.Errorf("parse p256 private key: %w", err)
		}
		// ECDSA signs a digest, not the message. cert.Sign uses SHA-256 here
		// and CheckSignature verifies the same way; changing this breaks
		// verification silently.
		hashed := sha256.Sum256(certBytes)
		return ecdsa.SignASN1(rand.Reader, pk, hashed[:])

	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}
