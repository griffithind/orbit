package ca

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/slackhq/nebula/cert"
)

// RemoteSigner is the narrow contract a hardware or cloud key backend must
// satisfy. It is deliberately smaller than Signer so that adapters for AWS KMS,
// GCP KMS, Azure Key Vault, Vault Transit, or PKCS#11 can be written without
// pulling their SDKs into this package (and therefore into every binary).
//
// The digest/format contract is the part implementers get wrong, so it is
// stated explicitly:
//
//	Curve_CURVE25519
//	    Sign the *message* certBytes directly with Ed25519 (PureEdDSA).
//	    Do not pre-hash. Return the 64-byte raw signature.
//	    Note: most cloud KMS products do not offer Ed25519. If yours does not,
//	    use a P-256 CA.
//
//	Curve_P256
//	    Sign SHA-256(certBytes) with ECDSA. Return an ASN.1 DER SEQUENCE of
//	    {r, s}. AWS KMS ECDSA_SHA_256 and GCP EC_SIGN_P256_SHA256 both return
//	    this form already. SignWith normalizes to low-S afterwards, so high-S
//	    responses are fine.
//
// PublicKey must return the same encoding cert.Certificate.PublicKey() uses:
// 32 raw bytes for Ed25519, uncompressed 0x04||X||Y for P-256.
type RemoteSigner interface {
	// KeyID identifies the backing key, for logging and audit records. It must
	// not contain secret material.
	KeyID() string

	// PublicKey fetches the raw public key bytes.
	PublicKey(ctx context.Context) ([]byte, error)

	// SignDigest performs the signing operation described above. The argument
	// is the raw certBytes; the implementation is responsible for hashing when
	// the curve requires it, because some backends hash server-side and some
	// do not.
	SignDigest(ctx context.Context, certBytes []byte) ([]byte, error)

	Close() error
}

// KMSSigner adapts a RemoteSigner to the Signer interface, adding public key
// caching so that issuance does not make a network round trip per certificate.
type KMSSigner struct {
	curve  cert.Curve
	remote RemoteSigner

	once sync.Once
	pub  []byte
	err  error
}

var _ Signer = (*KMSSigner)(nil)

// NewKMSSigner wraps a RemoteSigner. curve must match the key's actual
// algorithm; there is no way to detect it portably across backends, and a
// mismatch produces certificates that fail verification with a confusing
// ErrSignatureMismatch rather than a clear error, so it is required explicitly.
func NewKMSSigner(curve cert.Curve, remote RemoteSigner) (*KMSSigner, error) {
	switch curve {
	case cert.Curve_CURVE25519, cert.Curve_P256:
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
	if remote == nil {
		return nil, fmt.Errorf("remote signer is nil")
	}
	return &KMSSigner{curve: curve, remote: remote}, nil
}

func (s *KMSSigner) Curve() cert.Curve { return s.curve }

// Public fetches and caches the public key. The key is immutable for the life
// of the CA, so caching is safe; a rotation is a new CA and therefore a new
// signer.
func (s *KMSSigner) Public(ctx context.Context) ([]byte, error) {
	s.once.Do(func() {
		pub, err := s.remote.PublicKey(ctx)
		if err != nil {
			s.err = fmt.Errorf("%w: fetch public key for %s: %w", ErrSignerUnavailable, s.remote.KeyID(), err)
			return
		}
		if err := validatePublicKeyLength(s.curve, pub); err != nil {
			s.err = fmt.Errorf("backend %s returned an unusable public key: %w", s.remote.KeyID(), err)
			return
		}
		s.pub = pub
	})
	if s.err != nil {
		// Do not cache a transient failure forever. Reset so the next call
		// retries; sync.Once already ran, so swap in a fresh one.
		if errors.Is(s.err, ErrSignerUnavailable) {
			err := s.err
			s.once = sync.Once{}
			s.err = nil
			return nil, err
		}
		return nil, s.err
	}
	return bytes.Clone(s.pub), nil
}

func (s *KMSSigner) Sign(ctx context.Context, certBytes []byte) ([]byte, error) {
	sig, err := s.remote.SignDigest(ctx, certBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: sign with %s: %w", ErrSignerUnavailable, s.remote.KeyID(), err)
	}
	return sig, nil
}

func (s *KMSSigner) Close() error { return s.remote.Close() }

func validatePublicKeyLength(curve cert.Curve, pub []byte) error {
	switch curve {
	case cert.Curve_CURVE25519:
		if len(pub) != 32 {
			return fmt.Errorf("ed25519 public key must be 32 bytes, got %d", len(pub))
		}
	case cert.Curve_P256:
		// Uncompressed point: 0x04 || X(32) || Y(32)
		if len(pub) != 65 || pub[0] != 0x04 {
			return fmt.Errorf("p256 public key must be a 65 byte uncompressed point, got %d bytes", len(pub))
		}
	}
	return nil
}
