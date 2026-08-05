package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// deviceIssuer builds a P-256 CA and issuer for device certificate tests.
func deviceIssuer(t *testing.T) *Issuer {
	t.Helper()
	ctx := context.Background()

	pub, priv, err := GenerateCAKey(cert.Curve_P256)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	signer := NewMemorySigner(cert.Curve_P256, pub, priv)

	now := time.Now()
	caCert, err := CreateCA(ctx, signer, CAParams{
		Name:      "device-ca",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		Groups:    []string{"default"},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	iss, err := NewIssuer(ctx, caCert, signer)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	return iss
}

// devicePublicKey is the DER SubjectPublicKeyInfo of a fresh P-256 signing key,
// standing in for one generated on a host — ideally inside a token.
func devicePublicKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal device public key: %v", err)
	}
	return der
}

// TestIssueDeviceCert covers the shape of what gets signed.
//
// The certificate authenticates a machine to one service and must be useless
// anywhere else: a device credential that a browser or a server would also
// accept turns "this host may talk to the control plane" into something much
// broader than intended.
func TestIssueDeviceCert(t *testing.T) {
	ctx := context.Background()
	iss := deviceIssuer(t)
	pub := devicePublicKey(t)

	now := time.Now()
	der, err := iss.IssueDeviceCert(ctx, DeviceCertParams{
		MembershipID: "11111111-2222-3333-4444-555555555555",
		NetworkID:    "99999999-8888-7777-6666-555555555555",
		PublicKey:    pub,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue device cert: %v", err)
	}

	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}

	if c.Subject.CommonName != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("subject CN = %q, want the host id", c.Subject.CommonName)
	}
	if len(c.Subject.Organization) != 1 || c.Subject.Organization[0] != "99999999-8888-7777-6666-555555555555" {
		t.Errorf("subject O = %v, want the network id", c.Subject.Organization)
	}

	// Client authentication and nothing else.
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want exactly ClientAuth", c.ExtKeyUsage)
	}
	if c.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want DigitalSignature only", c.KeyUsage)
	}
	if c.IsCA {
		t.Error("device certificate has IsCA set; it must never sign anything")
	}
	if !c.BasicConstraintsValid {
		t.Error("BasicConstraints is absent; say IsCA=false rather than implying it")
	}
	// No names of any kind. A device certificate that carries a DNS SAN could
	// be presented as a server certificate for that name.
	if len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.EmailAddresses) != 0 || len(c.URIs) != 0 {
		t.Errorf("device certificate carries SANs: dns=%v ip=%v email=%v uri=%v",
			c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs)
	}

	// The issuer must name the CA, not the host. Getting this wrong produces a
	// certificate that verifies fine and tells an operator nothing about where
	// it came from.
	if c.Issuer.CommonName != "device-ca" {
		t.Errorf("issuer CN = %q, want the CA name", c.Issuer.CommonName)
	}
	if c.Issuer.CommonName == c.Subject.CommonName {
		t.Error("issuer equals subject; the certificate claims to be self-issued")
	}

	// Serials must be unpredictable, not sequential.
	if c.SerialNumber.BitLen() < 64 {
		t.Errorf("serial is only %d bits; want ~128 from crypto/rand", c.SerialNumber.BitLen())
	}
}

// TestIssueDeviceCertSignatureVerifiesAgainstTheCAKey.
//
// The whole point: a verifier holding only the CA's public key must be able to
// confirm this certificate. There is no chain to walk — nebula has no
// intermediates and the CA is not an X.509 certificate — so this single check
// is the entire trust decision, and it has to actually work.
func TestIssueDeviceCertSignatureVerifiesAgainstTheCAKey(t *testing.T) {
	ctx := context.Background()
	iss := deviceIssuer(t)

	der, err := iss.IssueDeviceCert(ctx, DeviceCertParams{
		MembershipID: "host-1",
		NetworkID:    "net-1",
		PublicKey:    devicePublicKey(t),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue device cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	caPub, err := iss.signer.Public(ctx)
	if err != nil {
		t.Fatalf("ca public: %v", err)
	}
	ecPub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), caPub)
	if err != nil {
		t.Fatalf("parse ca public: %v", err)
	}

	// Explicitly against the CA's key. x509.Certificate.CheckSignature verifies
	// against the certificate's OWN public key, which for a device certificate
	// is the host's — it would answer a different question entirely.
	if !ecdsa.VerifyASN1(ecPub, sha256Of(c.RawTBSCertificate), c.Signature) {
		t.Fatal("device certificate does not verify against the CA public key")
	}

	// And a certificate from a DIFFERENT CA must not verify against this one,
	// or the check above proves nothing.
	other := deviceIssuer(t)
	otherDER, err := other.IssueDeviceCert(ctx, DeviceCertParams{
		MembershipID: "host-1",
		NetworkID:    "net-1",
		PublicKey:    devicePublicKey(t),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue from other ca: %v", err)
	}
	oc, err := x509.ParseCertificate(otherDER)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ecdsa.VerifyASN1(ecPub, sha256Of(oc.RawTBSCertificate), oc.Signature) {
		t.Fatal("a certificate from an unrelated CA verified against this CA's key")
	}
}

// TestIssueDeviceCertRequiresP256 pins the refusal. A CURVE25519 network signs
// with Ed25519, which signs messages rather than digests — there is no correct
// thing to do, so the error must name the reason and the fix.
func TestIssueDeviceCertRequiresP256(t *testing.T) {
	ctx := context.Background()

	pub, priv, err := GenerateCAKey(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	signer := NewMemorySigner(cert.Curve_CURVE25519, pub, priv)
	now := time.Now()
	caCert, err := CreateCA(ctx, signer, CAParams{
		Name:      "ed-ca",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		Groups:    []string{"default"},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	iss, err := NewIssuer(ctx, caCert, signer)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	_, err = iss.IssueDeviceCert(ctx, DeviceCertParams{
		MembershipID: "host-1",
		NetworkID:    "net-1",
		PublicKey:    devicePublicKey(t),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	})
	if err == nil {
		t.Fatal("issued a device certificate from a CURVE25519 CA")
	}
	for _, want := range []string{"P-256", "bootstrap"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestIssueDeviceCertRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	iss := deviceIssuer(t)
	now := time.Now()
	good := DeviceCertParams{
		MembershipID: "host-1",
		NetworkID:    "net-1",
		PublicKey:    devicePublicKey(t),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	}

	for name, mutate := range map[string]func(*DeviceCertParams){
		"no host id":     func(p *DeviceCertParams) { p.MembershipID = "" },
		"no network id":  func(p *DeviceCertParams) { p.NetworkID = "" },
		"no public key":  func(p *DeviceCertParams) { p.PublicKey = nil },
		"garbage key":    func(p *DeviceCertParams) { p.PublicKey = []byte("not der") },
		"empty validity": func(p *DeviceCertParams) { p.NotAfter = p.NotBefore },
		"inverted validity": func(p *DeviceCertParams) {
			p.NotAfter = p.NotBefore.Add(-time.Hour)
		},
	} {
		p := good
		mutate(&p)
		if _, err := iss.IssueDeviceCert(ctx, p); err == nil {
			t.Errorf("%s: issued anyway", name)
		}
	}
}

// TestSignDigestBytesRefusesWhatItCannotDo.
//
// The digest path is separate from SignBytes precisely because confusing the
// two produces a signature that verifies against nothing. Both refusals must be
// loud.
func TestSignDigestBytesRefusesWhatItCannotDo(t *testing.T) {
	_, priv, err := GenerateCAKey(cert.Curve_P256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	digest := sha256Of([]byte("hello"))

	if _, err := SignDigestBytes(cert.Curve_CURVE25519, priv, digest, crypto.SHA256); err == nil {
		t.Error("signed a digest on CURVE25519")
	} else if !errors.Is(err, ErrDigestSigningUnsupported) {
		t.Errorf("curve refusal = %v, want ErrDigestSigningUnsupported", err)
	}

	if _, err := SignDigestBytes(cert.Curve_P256, priv, digest[:16], crypto.SHA256); err == nil {
		t.Error("signed a short digest")
	}
}
