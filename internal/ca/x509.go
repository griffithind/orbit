package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/slackhq/nebula/cert"
)

// X.509 device certificates.
//
// A second credential, alongside the nebula certificate, answering a different
// question. The nebula certificate says which hosts this machine may exchange
// packets with; this one says the machine is who it claims to be when it talks
// to the CONTROL PLANE — over ordinary TLS, with no overlay involved.
//
// Why both: today the agent surface is reachable only over the mesh, so a host
// must have a working tunnel to renew the certificate that gives it a working
// tunnel. `orbit agent recover` exists to break that circle. Worse, a host whose
// data plane is broken cannot report that its data plane is broken — the
// control plane sees silence, which looks exactly like a laptop that is closed.
//
// See docs/design-device-identity.md.
//
// Two keys, not one. A signing key and a key-agreement key are different
// nebula's Noise handshake needs ECDH (PKCS#11 CKA_DERIVE), TLS client
// authentication needs ECDSA (CKA_SIGN), and no token will do both with one
// object. A token-backed host therefore holds two non-exportable P-256 keys.

// ErrDigestSigningUnsupported means the CA's signer cannot sign a pre-computed
// digest, which X.509 requires.
//
// Distinct from a signing failure: the fix is a different CA backend, not a
// retry. Every in-process signer supports it; a remote backend may not.
var ErrDigestSigningUnsupported = errors.New("this signer cannot sign a digest, which X.509 issuance requires")

// DigestSigner is the optional half of Signer needed for X.509.
//
// Signer.Sign takes the MESSAGE and hashes it internally, because that is what
// nebula's certificate format wants. crypto.Signer — and therefore
// x509.CreateCertificate — hands over an already-computed digest and expects it
// signed as-is. The two cannot be bridged by forwarding: recovering a message
// whose hash equals a given digest is the preimage problem.
//
// So signers that hold or can reach the key material declare this separately.
type DigestSigner interface {
	// SignDigest returns an ASN.1 ECDSA signature over an already-hashed
	// digest. hash names the algorithm that produced it, so an implementation
	// can reject one it does not support rather than signing the wrong thing.
	SignDigest(ctx context.Context, digest []byte, hash crypto.Hash) ([]byte, error)
}

// x509Signer adapts a ca.Signer to crypto.Signer for x509.CreateCertificate.
//
// Holds a context because crypto.Signer has nowhere to put one and the
// underlying signer may be a network call.
type x509Signer struct {
	ctx    context.Context
	digest DigestSigner
	pub    crypto.PublicKey
}

func (s x509Signer) Public() crypto.PublicKey { return s.pub }

func (s x509Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.digest.SignDigest(s.ctx, digest, opts.HashFunc())
}

// x509SignerFor builds the crypto.Signer x509.CreateCertificate needs.
//
// P-256 only, and deliberately so. SignBytes already produces ASN.1 ECDSA over
// SHA-256 for this curve, which is exactly what X.509 expects; Ed25519 would
// need x509.PureEd25519 and a signer that takes the whole message rather than a
// digest — a second code path for a curve Orbit no longer creates
// anyway.
func x509SignerFor(ctx context.Context, s Signer) (crypto.Signer, error) {
	if s.Curve() != cert.Curve_P256 {
		return nil, fmt.Errorf(
			"X.509 device certificates require a P-256 CA, this one is %s "+
				"(a network's curve is fixed at bootstrap: see `orbitd bootstrap -curve`)",
			s.Curve())
	}
	ds, ok := s.(DigestSigner)
	if !ok {
		return nil, ErrDigestSigningUnsupported
	}
	rawPub, err := s.Public(ctx)
	if err != nil {
		return nil, fmt.Errorf("read CA public key: %w", err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), rawPub)
	if err != nil {
		return nil, fmt.Errorf("parse CA public key: %w", err)
	}
	return x509Signer{ctx: ctx, digest: ds, pub: pub}, nil
}

// DeviceCertParams describes an X.509 device certificate.
type DeviceCertParams struct {
	// MembershipID is the subject. A UUID rather than a hostname: the control plane
	// looks a host up by it, and a name can be changed while an identity cannot.
	MembershipID string

	// NetworkID scopes the certificate. A host enrolled in two networks holds
	// two device certificates, because the two control planes need not trust
	// each other.
	NetworkID string

	// PublicKey is the DER SubjectPublicKeyInfo of the host's signing key —
	// generated on the host, ideally inside a token, and never seen here.
	PublicKey []byte

	NotBefore time.Time
	NotAfter  time.Time
}

// IssueDeviceCert signs an X.509 client certificate for a host.
//
// Deliberately minimal: client authentication only, no CA bit, no DNS or IP
// SANs. It authenticates a machine to one service. Anything broader would make
// it useful somewhere it was never meant to be accepted.
//
// The certificate authenticates; it authorizes nothing. What a host may do
// remains a function of policy and posture evaluated at issuance — see
// docs/credential-model.md §3.
func (i *Issuer) IssueDeviceCert(ctx context.Context, p DeviceCertParams) ([]byte, error) {
	if p.MembershipID == "" {
		return nil, errors.New("device certificate requires a host id")
	}
	if p.NetworkID == "" {
		return nil, errors.New("device certificate requires a network id")
	}
	if len(p.PublicKey) == 0 {
		return nil, errors.New("device certificate requires a public key")
	}
	if !p.NotAfter.After(p.NotBefore) {
		return nil, fmt.Errorf("device certificate validity is empty: %s to %s", p.NotBefore, p.NotAfter)
	}

	signer, err := x509SignerFor(ctx, i.signer)
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(p.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse device public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != elliptic.P256() {
		return nil, errors.New("device public key must be ECDSA P-256")
	}

	// 128 bits from crypto/rand. Serials must be unpredictable — a guessable
	// one lets an attacker who can influence certificate contents mount a
	// collision attack against the signature — and unique, which random 128-bit
	// values are with overwhelming probability and without needing a counter
	// the database would have to serialize.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   p.MembershipID,
			Organization: []string{p.NetworkID},
		},
		NotBefore: p.NotBefore,
		NotAfter:  p.NotAfter,

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		// BasicConstraints present and IsCA false, explicitly. A certificate
		// that omits the extension is not a CA either, but saying so is the
		// difference between a policy and an accident.
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// The CA is a nebula certificate, not an X.509 one, so there is no issuer
	// certificate to chain to. x509.CreateCertificate still needs a parent to
	// take the issuer name from, so synthesize one that names the actual CA.
	//
	// Passing tmpl as its own parent would be simpler and would produce a
	// certificate whose Issuer equals its Subject — one that claims to be
	// self-issued by the host. It would verify identically, and it would be a
	// lie in a field an operator reads when working out where a certificate
	// came from.
	//
	// The CA fingerprint rather than only the name: names are not unique across
	// networks and a CA rotation reuses them, so the fingerprint is what
	// actually identifies which key signed this.
	fp, err := i.caCert.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("ca fingerprint: %w", err)
	}
	parent := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   i.caCert.Name(),
			SerialNumber: fp,
		},
	}

	// Verification is "was this signed by the CA key we hold", not path
	// building. Nebula has no intermediates and neither does this: a verifier
	// checks the signature against the one public key it already trusts.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, ecPub, signer)
	if err != nil {
		return nil, fmt.Errorf("create device certificate: %w", err)
	}
	return der, nil
}
