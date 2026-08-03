package ca

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/slackhq/nebula/cert"
)

// Validation errors. These are all conditions nebula would also reject, either
// at signing time (checkCAConstraints) or at verification time on every peer.
// Orbit checks them first so the API returns an actionable 4xx instead of
// issuing a certificate that silently fails to verify across the mesh.
var (
	ErrNoName            = errors.New("certificate name is required")
	ErrNoNetworks        = errors.New("at least one network is required")
	ErrNoPublicKey       = errors.New("public key is required")
	ErrInvalidValidity   = errors.New("NotAfter must be after NotBefore")
	ErrOutsideCAValidity = errors.New("requested validity is not contained by the CA validity window")
	ErrNetworkNotInCA    = errors.New("requested network is not contained by a CA network")
	ErrGroupNotInCA      = errors.New("requested group is not permitted by the CA")
	ErrUnroutableAddr    = errors.New("network must be a specific address, not a bare prefix")
)

// CAParams describes a certificate authority to create.
//
// Scope these narrowly. Nebula enforces every field below as a hard constraint
// on all subordinate certificates, so a CA is the only mechanism available for
// bounding the damage from a compromised signing path. An unconstrained CA
// (empty Networks and Groups) can mint any identity in the mesh, which is why
// the API layer refuses to create one.
type CAParams struct {
	Name string

	// Version defaults to cert.Version2. Version1 is IPv4-only and supports a
	// single network; prefer v2 unless you must interoperate with hosts that
	// predate v2 support.
	Version cert.Version

	// Networks bounds the overlay addresses subordinate certs may claim.
	// Leaving this empty produces an unconstrained CA, which this package
	// permits and the API layer refuses.
	Networks []netip.Prefix

	// UnsafeNetworks bounds which external routes subordinate certs may
	// advertise. Empty means subordinate certs may advertise none.
	UnsafeNetworks []netip.Prefix

	// Groups bounds the firewall groups subordinate certs may carry. Empty
	// means unconstrained, which is usually wrong.
	Groups []string

	NotBefore time.Time
	NotAfter  time.Time
}

// HostParams describes a host certificate to issue.
type HostParams struct {
	Name string

	// Version defaults to the issuing CA's version.
	Version cert.Version

	// Networks are the specific overlay addresses assigned to this host,
	// carrying the prefix length of the network they belong to
	// (e.g. 10.42.0.7/16, not 10.42.0.0/16). Nebula derives the host's address
	// from Addr() and the routable network from the prefix.
	Networks []netip.Prefix

	UnsafeNetworks []netip.Prefix
	Groups         []string

	// PublicKey is the host's raw X25519 or ECDH P-256 public key. It is
	// generated on the host and never leaves it; Orbit only ever sees the
	// public half.
	PublicKey []byte

	NotBefore time.Time
	NotAfter  time.Time
}

// Issuer mints host certificates from a single CA.
//
// An Issuer is bound to exactly one CA certificate and one Signer, and the
// binding is immutable. That is what keeps networks separate: an Issuer is
// constructed from one network's CA record, so there is no code path that can
// sign with a different network's key. Do not add a method that selects a CA at
// signing time.
type Issuer struct {
	caCert cert.Certificate
	signer Signer

	// now is injectable for tests. Production callers leave it nil.
	now func() time.Time
}

// NewIssuer binds a CA certificate to the signer that holds its private key.
// It verifies that the signer actually corresponds to the CA, which catches the
// single most damaging misconfiguration in a multi-CA deployment: pairing CA A's
// certificate with CA B's key produces certificates that fail verification
// everywhere, and the failure surfaces on peers rather than here.
func NewIssuer(ctx context.Context, caCert cert.Certificate, signer Signer) (*Issuer, error) {
	if caCert == nil {
		return nil, errors.New("ca certificate is nil")
	}
	if !caCert.IsCA() {
		return nil, fmt.Errorf("%s is not a CA certificate", caCert.Name())
	}
	if signer == nil {
		return nil, errors.New("signer is nil")
	}
	if caCert.Curve() != signer.Curve() {
		return nil, fmt.Errorf("%w: ca is %s, signer is %s", ErrCurveMismatch, caCert.Curve(), signer.Curve())
	}

	pub, err := signer.Public(ctx)
	if err != nil {
		return nil, fmt.Errorf("read signer public key: %w", err)
	}
	if !slices.Equal(pub, caCert.PublicKey()) {
		return nil, fmt.Errorf("signer public key does not match CA %q", caCert.Name())
	}

	// A self-signature check is cheap and proves the CA cert is internally
	// consistent before we start minting against it.
	if !caCert.CheckSignature(caCert.PublicKey()) {
		return nil, fmt.Errorf("ca %q is not self-signed; nebula's CAPool will reject it", caCert.Name())
	}

	return &Issuer{caCert: caCert, signer: signer}, nil
}

// Certificate returns the CA certificate this issuer signs with.
func (i *Issuer) Certificate() cert.Certificate { return i.caCert }

// Fingerprint returns the CA's fingerprint, which is the identifier nebula uses
// as the issuer field on every certificate this Issuer produces.
func (i *Issuer) Fingerprint() (string, error) { return i.caCert.Fingerprint() }

func (i *Issuer) clock() time.Time {
	if i.now != nil {
		return i.now()
	}
	return time.Now()
}

// CreateCA produces a self-signed nebula CA certificate using signer.
//
// The signer must already hold the key pair; this function never generates key
// material, because a CA key that was generated in the control plane's address
// space has, by definition, existed in the control plane's address space. Use
// GenerateCAKey only for development and tests.
func CreateCA(ctx context.Context, signer Signer, p CAParams) (cert.Certificate, error) {
	if p.Name == "" {
		return nil, ErrNoName
	}
	if !p.NotAfter.After(p.NotBefore) {
		return nil, ErrInvalidValidity
	}
	if p.Version == 0 {
		p.Version = cert.Version2
	}

	pub, err := signer.Public(ctx)
	if err != nil {
		return nil, fmt.Errorf("read signer public key: %w", err)
	}

	tbs := &cert.TBSCertificate{
		Version:        p.Version,
		Name:           p.Name,
		Networks:       p.Networks,
		UnsafeNetworks: p.UnsafeNetworks,
		Groups:         p.Groups,
		IsCA:           true,
		NotBefore:      p.NotBefore,
		NotAfter:       p.NotAfter,
		PublicKey:      pub,
		Curve:          signer.Curve(),
	}

	// signer==nil in SignWith means "self-signed", which is the only shape
	// nebula's CAPool accepts. See cert/ca_pool.go AddCA.
	c, err := tbs.SignWith(nil, signer.Curve(), lambda(ctx, signer))
	if err != nil {
		return nil, fmt.Errorf("sign ca certificate: %w", err)
	}
	return c, nil
}

// ValidityFor returns a NotBefore/NotAfter pair for a certificate of the given
// lifetime, clamped to fit inside the CA's own validity window.
//
// This exists because the naive choice fails in a way that is easy to hit and
// annoying to debug. `nebula-cert ca` sets the CA's NotBefore to its creation
// time, so the common idiom of backdating a leaf by a minute to absorb clock
// skew produces a NotBefore that precedes the CA's, which nebula rejects. A
// freshly created CA therefore cannot sign a backdated certificate at all.
//
// skew is how far back to set NotBefore to tolerate clock drift between the
// control plane and the host; it is silently reduced when the CA is younger
// than that.
//
// Returns an error if the CA has already expired or expires so soon that no
// usable certificate can be issued, which is a condition the caller must
// surface rather than paper over: it means CA rotation is overdue.
func (i *Issuer) ValidityFor(ttl, skew time.Duration) (notBefore, notAfter time.Time, err error) {
	now := i.clock()

	if !now.Before(i.caCert.NotAfter()) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: CA %q expired at %s",
			ErrOutsideCAValidity, i.caCert.Name(), i.caCert.NotAfter().UTC().Format(time.RFC3339))
	}

	notBefore = now.Add(-skew)
	if notBefore.Before(i.caCert.NotBefore()) {
		notBefore = i.caCert.NotBefore()
	}

	notAfter = now.Add(ttl)
	if notAfter.After(i.caCert.NotAfter()) {
		notAfter = i.caCert.NotAfter()
	}

	if !notAfter.After(notBefore) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: CA %q leaves no usable validity window",
			ErrOutsideCAValidity, i.caCert.Name())
	}
	return notBefore, notAfter, nil
}

// IssueHost mints a host certificate.
//
// All constraint checks are performed before signing so that a rejected request
// never consumes a KMS/HSM signing operation (which is both billable and
// rate-limited) and never produces an audit record for a certificate that does
// not exist.
func (i *Issuer) IssueHost(ctx context.Context, p HostParams) (cert.Certificate, error) {
	if err := i.validateHost(p); err != nil {
		return nil, err
	}

	version := p.Version
	if version == 0 {
		version = i.caCert.Version()
	}

	tbs := &cert.TBSCertificate{
		Version:        version,
		Name:           p.Name,
		Networks:       p.Networks,
		UnsafeNetworks: p.UnsafeNetworks,
		Groups:         p.Groups,
		IsCA:           false,
		NotBefore:      p.NotBefore,
		NotAfter:       p.NotAfter,
		PublicKey:      p.PublicKey,
		Curve:          i.caCert.Curve(),
	}

	c, err := tbs.SignWith(i.caCert, i.signer.Curve(), lambda(ctx, i.signer))
	if err != nil {
		return nil, fmt.Errorf("sign host certificate: %w", err)
	}
	return c, nil
}

// validateHost reproduces nebula's constraint checks with actionable errors.
//
// It is intentionally strict about things nebula tolerates but that indicate a
// bug in the caller, most importantly a bare network prefix where a host
// address was meant. `10.42.0.0/16` is a legal prefix but assigns the host the
// network address, which will not route.
func (i *Issuer) validateHost(p HostParams) error {
	if p.Name == "" {
		return ErrNoName
	}
	if len(p.PublicKey) == 0 {
		return ErrNoPublicKey
	}
	if len(p.Networks) == 0 {
		return ErrNoNetworks
	}
	if !p.NotAfter.After(p.NotBefore) {
		return ErrInvalidValidity
	}

	// Nebula requires the leaf validity window to sit inside the CA's, and
	// rejects the certificate at signing time otherwise. Report which end.
	if p.NotBefore.Before(i.caCert.NotBefore()) {
		return fmt.Errorf("%w: NotBefore %s precedes CA NotBefore %s",
			ErrOutsideCAValidity, p.NotBefore.UTC().Format(time.RFC3339), i.caCert.NotBefore().UTC().Format(time.RFC3339))
	}
	if p.NotAfter.After(i.caCert.NotAfter()) {
		return fmt.Errorf("%w: NotAfter %s exceeds CA NotAfter %s",
			ErrOutsideCAValidity, p.NotAfter.UTC().Format(time.RFC3339), i.caCert.NotAfter().UTC().Format(time.RFC3339))
	}

	for _, n := range p.Networks {
		if !n.IsValid() {
			return fmt.Errorf("%w: %s", ErrNetworkNotInCA, n)
		}
		if n.Addr() == n.Masked().Addr() && n.Addr().BitLen() != n.Bits() {
			// The address equals the network address of its own prefix. This is
			// almost always a caller passing the network instead of the host.
			return fmt.Errorf("%w: %s looks like a network, not a host address", ErrUnroutableAddr, n)
		}
	}

	if err := containedBy(p.Networks, i.caCert.Networks()); err != nil {
		return err
	}
	if err := containedBy(p.UnsafeNetworks, i.caCert.UnsafeNetworks()); err != nil {
		return err
	}

	caGroups := i.caCert.Groups()
	if len(caGroups) > 0 {
		for _, g := range p.Groups {
			if !slices.Contains(caGroups, g) {
				return fmt.Errorf("%w: %q (CA permits %v)", ErrGroupNotInCA, g, caGroups)
			}
		}
	}

	return nil
}

// containedBy verifies every prefix in want is inside at least one prefix in
// allowed. An empty allowed list means the CA placed no constraint, which
// nebula treats as "anything goes".
func containedBy(want, allowed []netip.Prefix) error {
	if len(allowed) == 0 {
		return nil
	}
	for _, w := range want {
		ok := false
		for _, a := range allowed {
			// Containment requires the same address family and a prefix at
			// least as specific as the constraint.
			if a.Addr().BitLen() != w.Addr().BitLen() {
				continue
			}
			if a.Contains(w.Addr()) && w.Bits() >= a.Bits() {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: %s not within %v", ErrNetworkNotInCA, w, allowed)
		}
	}
	return nil
}
