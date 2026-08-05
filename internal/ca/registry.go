package ca

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/slackhq/nebula/cert"
)

// SignerFactory resolves an opaque signer reference into a Signer.
//
// References are URLs so that adding a backend does not change any stored data:
//
//	db://<uuid>                    the vault: sealed in Postgres under the KEK
//	awskms://<region>/<key-id>     not implemented
//	pkcs11://<token>?<params>      not implemented
//
// `file://` was REMOVED, not deprecated — internal/vault rejects it by name.
// Two custody schemes meant two things to back up, two ways to lose a network,
// and a replica that could silently hold a stale key. See docs/key-custody.md.
//
// No scheme is built in. Each is registered by the binary that needs it, so the
// core does not carry a cloud SDK it may never use.
type SignerFactory func(ctx context.Context, ref string) (Signer, error)

// Registry turns stored CA rows into ready-to-use Issuers, caching the result.
//
// Caching matters for more than latency: a KMS-backed signer holds a client and
// a cached public key, and constructing one per issuance would make every
// certificate cost an extra round trip and count against the backend's rate
// limit.
//
// Cache keys are CA fingerprints, which are content-addressed. A rotated CA is
// a different fingerprint and therefore a different entry, so a stale Issuer can
// never outlive the CA it was built from.
type Registry struct {
	factory SignerFactory

	mu    sync.Mutex
	cache map[string]*Issuer
}

// A nil factory is a programming error rather than a default, and fails on the
// first issuance rather than here. There is nothing sensible to fall back to:
// the only backend is the vault, and the vault needs a database handle and a
// KEK that this package must never hold.
func NewRegistry(f SignerFactory) *Registry {
	return &Registry{factory: f, cache: map[string]*Issuer{}}
}

// Issuer returns the Issuer for a stored CA.
//
// caPEM and signerRef come from the same database row, so this materializes the
// CA the caller already fetched rather than selecting one. There is deliberately
// no lookup-by-network here: choosing a CA is the caller's decision, made once,
// and an Issuer is immutably bound to the result.
func (r *Registry) Issuer(ctx context.Context, fingerprint, caPEM, signerRef string) (*Issuer, error) {
	r.mu.Lock()
	if iss, ok := r.cache[fingerprint]; ok {
		r.mu.Unlock()
		return iss, nil
	}
	r.mu.Unlock()

	caCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(caPEM))
	if err != nil {
		return nil, fmt.Errorf("parse stored ca certificate: %w", err)
	}

	signer, err := r.factory(ctx, signerRef)
	if err != nil {
		return nil, fmt.Errorf("resolve signer %q: %w", signerRef, err)
	}

	// NewIssuer verifies the signer's public key matches the CA, which catches
	// a mis-recorded signer_ref here rather than as certificates that fail to
	// verify across the whole fleet.
	iss, err := NewIssuer(ctx, caCert, signer)
	if err != nil {
		_ = signer.Close()
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Another goroutine may have won the race; keep theirs and discard ours so
	// there is exactly one Signer per CA holding backend resources.
	if existing, ok := r.cache[fingerprint]; ok {
		_ = signer.Close()
		return existing, nil
	}
	r.cache[fingerprint] = iss
	return iss, nil
}

// Close releases every cached signer.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, iss := range r.cache {
		_ = iss.signer.Close()
	}
	r.cache = map[string]*Issuer{}
	return nil
}

// ChainFactories tries each factory in order, returning the first success. Use
// it to compose the built-in file scheme with a KMS factory the binary
// registers.
func ChainFactories(factories ...SignerFactory) SignerFactory {
	return func(ctx context.Context, ref string) (Signer, error) {
		var errs []string
		for _, f := range factories {
			s, err := f(ctx, ref)
			if err == nil {
				return s, nil
			}
			errs = append(errs, err.Error())
		}
		return nil, fmt.Errorf("no factory handled %q: %s", ref, strings.Join(errs, "; "))
	}
}
