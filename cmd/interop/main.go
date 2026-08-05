// Command interop proves Orbit's CA service is wire-compatible with the stock
// nebula-cert tooling in both directions: it loads a CA produced by
// `nebula-cert ca` and mints a host certificate that `nebula-cert print` and
// `nebula-cert verify` accept.
//
// This is a manual harness, not a test. See internal/ca/ca_test.go for the
// automated coverage.
package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/slackhq/nebula/cert"
)

func main() {
	ctx := context.Background()

	// 1. Load the CA key and cert that nebula-cert produced.
	signer, err := ca.NewFileSignerFromPath("ca.key", nil)
	if err != nil {
		log.Fatalf("load ca key: %v", err)
	}
	defer signer.Close()

	caPEM, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("read ca.crt: %v", err)
	}
	caCert, _, err := cert.UnmarshalCertificateFromPEM(caPEM)
	if err != nil {
		log.Fatalf("parse ca.crt: %v", err)
	}

	// NewIssuer verifies the key actually belongs to this CA.
	issuer, err := ca.NewIssuer(ctx, caCert, signer)
	if err != nil {
		log.Fatalf("new issuer: %v", err)
	}
	fmt.Println("loaded nebula-cert CA into orbit:", caCert.Name())

	// 2. Generate a host keypair the way an agent would, and issue against it.
	pub, priv, err := ca.GenerateHostKey(cert.Curve_CURVE25519)
	if err != nil {
		log.Fatalf("generate host key: %v", err)
	}

	// ValidityFor clamps to the CA's window. A CA that nebula-cert created
	// seconds ago has NotBefore == now, so a naively backdated leaf is rejected.
	notBefore, notAfter, err := issuer.ValidityFor(24*time.Hour, time.Minute)
	if err != nil {
		log.Fatalf("validity: %v", err)
	}

	membershipCert, err := issuer.IssueHost(ctx, ca.HostParams{
		Name:      "web-01",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.7/16")},
		Groups:    []string{"web"},
		PublicKey: pub,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})
	if err != nil {
		log.Fatalf("issue host cert: %v", err)
	}

	hostPEM, err := membershipCert.MarshalPEM()
	if err != nil {
		log.Fatalf("marshal host cert: %v", err)
	}
	if err := os.WriteFile("host.crt", hostPEM, 0644); err != nil {
		log.Fatalf("write host.crt: %v", err)
	}
	if err := os.WriteFile("host.key", cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv), 0600); err != nil {
		log.Fatalf("write host.key: %v", err)
	}

	fmt.Println("issued host.crt via orbit; verify it with nebula-cert")
}
