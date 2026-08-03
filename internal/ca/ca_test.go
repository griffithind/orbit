package ca

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// The tests below all end by verifying against a real cert.CAPool. That is the
// point: it is the same code every nebula host runs, so a certificate that
// passes here is one the mesh will actually accept. Asserting only on our own
// validation would prove nothing.

func testIssuer(t *testing.T, curve cert.Curve, p CAParams) (*Issuer, Signer) {
	t.Helper()
	ctx := context.Background()

	pub, priv, err := GenerateCAKey(curve)
	if err != nil {
		t.Fatalf("GenerateCAKey: %v", err)
	}
	signer := NewMemorySigner(curve, pub, priv)

	caCert, err := CreateCA(ctx, signer, p)
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	iss, err := NewIssuer(ctx, caCert, signer)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss, signer
}

func defaultCAParams(t *testing.T) CAParams {
	t.Helper()
	now := time.Now()
	return CAParams{
		Name:      "orbit-test-ca",
		Version:   cert.Version2,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		Groups:    []string{"prod", "web", "db"},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(90 * 24 * time.Hour),
	}
}

func poolFor(t *testing.T, cas ...cert.Certificate) *cert.CAPool {
	t.Helper()
	pool := cert.NewCAPool()
	for _, c := range cas {
		if err := pool.AddCA(c); err != nil {
			t.Fatalf("AddCA(%s): %v", c.Name(), err)
		}
	}
	return pool
}

func hostParams(t *testing.T, curve cert.Curve, addr string, groups []string) HostParams {
	t.Helper()
	pub, _, err := GenerateHostKey(curve)
	if err != nil {
		t.Fatalf("GenerateHostKey: %v", err)
	}
	now := time.Now()
	return HostParams{
		Name:      "host-" + addr,
		Networks:  []netip.Prefix{netip.MustParsePrefix(addr)},
		Groups:    groups,
		PublicKey: pub,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(24 * time.Hour),
	}
}

// TestIssueAndVerify covers the happy path on both curves. It is table-driven
// over the curve because the signing key type differs (Ed25519 vs ECDSA) and
// that difference has historically been where encoding bugs hide.
func TestIssueAndVerify(t *testing.T) {
	for _, curve := range []cert.Curve{cert.Curve_CURVE25519, cert.Curve_P256} {
		t.Run(curve.String(), func(t *testing.T) {
			ctx := context.Background()
			iss, _ := testIssuer(t, curve, defaultCAParams(t))

			hc, err := iss.IssueHost(ctx, hostParams(t, curve, "10.42.0.7/16", []string{"web"}))
			if err != nil {
				t.Fatalf("IssueHost: %v", err)
			}

			pool := poolFor(t, iss.Certificate())
			cached, err := pool.VerifyCertificate(time.Now(), hc)
			if err != nil {
				t.Fatalf("VerifyCertificate: %v", err)
			}
			if cached.Certificate.Name() != hc.Name() {
				t.Errorf("verified cert name = %q, want %q", cached.Certificate.Name(), hc.Name())
			}

			// The issuer field must be the CA fingerprint; this is what
			// CAPool.GetCAForCert looks up, and a mismatch means the cert can
			// never be verified by anyone.
			caFp, err := iss.Fingerprint()
			if err != nil {
				t.Fatalf("Fingerprint: %v", err)
			}
			if hc.Issuer() != caFp {
				t.Errorf("issuer = %q, want CA fingerprint %q", hc.Issuer(), caFp)
			}
		})
	}
}

// TestRoundTripPEM proves the certificates we mint survive the exact
// serialization path the agent will use to write them to disk.
func TestRoundTripPEM(t *testing.T) {
	ctx := context.Background()
	iss, _ := testIssuer(t, cert.Curve_CURVE25519, defaultCAParams(t))

	hc, err := iss.IssueHost(ctx, hostParams(t, cert.Curve_CURVE25519, "10.42.1.9/16", []string{"db"}))
	if err != nil {
		t.Fatalf("IssueHost: %v", err)
	}

	pemBytes, err := hc.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	parsed, rest, err := cert.UnmarshalCertificateFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("UnmarshalCertificateFromPEM: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("trailing bytes after cert PEM: %d", len(rest))
	}

	pool := poolFor(t, iss.Certificate())
	if _, err := pool.VerifyCertificate(time.Now(), parsed); err != nil {
		t.Fatalf("VerifyCertificate after PEM round trip: %v", err)
	}
}

// TestCAConstraintsEnforced is the blast-radius test. Because nebula has no
// intermediate CAs, a scoped CA is the only thing limiting what a compromised
// signing path can mint, so each of these must fail closed.
func TestCAConstraintsEnforced(t *testing.T) {
	ctx := context.Background()
	caParams := defaultCAParams(t)
	iss, _ := testIssuer(t, cert.Curve_CURVE25519, caParams)

	tests := []struct {
		name    string
		mutate  func(*HostParams)
		wantErr error
	}{
		{
			name:    "network outside CA range",
			mutate:  func(p *HostParams) { p.Networks = []netip.Prefix{netip.MustParsePrefix("10.99.0.5/16")} },
			wantErr: ErrNetworkNotInCA,
		},
		{
			name:    "group not permitted by CA",
			mutate:  func(p *HostParams) { p.Groups = []string{"admin"} },
			wantErr: ErrGroupNotInCA,
		},
		{
			name:    "validity extends past CA expiry",
			mutate:  func(p *HostParams) { p.NotAfter = caParams.NotAfter.Add(time.Hour) },
			wantErr: ErrOutsideCAValidity,
		},
		{
			name:    "validity starts before CA",
			mutate:  func(p *HostParams) { p.NotBefore = caParams.NotBefore.Add(-time.Hour) },
			wantErr: ErrOutsideCAValidity,
		},
		{
			name:    "bare network instead of host address",
			mutate:  func(p *HostParams) { p.Networks = []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")} },
			wantErr: ErrUnroutableAddr,
		},
		{
			name:    "missing public key",
			mutate:  func(p *HostParams) { p.PublicKey = nil },
			wantErr: ErrNoPublicKey,
		},
		{
			name:    "missing name",
			mutate:  func(p *HostParams) { p.Name = "" },
			wantErr: ErrNoName,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := hostParams(t, cert.Curve_CURVE25519, "10.42.0.7/16", []string{"web"})
			tc.mutate(&p)

			_, err := iss.IssueHost(ctx, p)
			if err == nil {
				t.Fatal("IssueHost succeeded, want error")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("IssueHost error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestUnconstrainedCA documents the behaviour Orbit's API layer must refuse to
// expose: a CA with no networks and no groups can mint anything. The test
// exists so that if nebula ever changes this, we find out.
func TestUnconstrainedCA(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	iss, _ := testIssuer(t, cert.Curve_CURVE25519, CAParams{
		Name:      "unconstrained",
		Version:   cert.Version2,
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
	})

	// Any address, any group.
	p := hostParams(t, cert.Curve_CURVE25519, "192.0.2.10/24", []string{"anything-at-all"})
	p.NotAfter = now.Add(time.Hour)
	hc, err := iss.IssueHost(ctx, p)
	if err != nil {
		t.Fatalf("IssueHost on unconstrained CA: %v", err)
	}
	if _, err := poolFor(t, iss.Certificate()).VerifyCertificate(time.Now(), hc); err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
}

// TestBlocklistRevocation exercises the only revocation mechanism nebula has.
// See docs/revocation.md: this check is what every host performs on every
// tunnel every few seconds, and it is driven entirely by config distribution.
func TestBlocklistRevocation(t *testing.T) {
	ctx := context.Background()
	iss, _ := testIssuer(t, cert.Curve_CURVE25519, defaultCAParams(t))

	hc, err := iss.IssueHost(ctx, hostParams(t, cert.Curve_CURVE25519, "10.42.0.7/16", []string{"web"}))
	if err != nil {
		t.Fatalf("IssueHost: %v", err)
	}

	pool := poolFor(t, iss.Certificate())
	cached, err := pool.VerifyCertificate(time.Now(), hc)
	if err != nil {
		t.Fatalf("VerifyCertificate before blocklist: %v", err)
	}

	fp, err := hc.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	pool.BlocklistFingerprint(fp)

	// Both the cold and the cached path must reject. The cached path is the one
	// connection_manager.go uses on live tunnels, so it is the one that
	// actually tears a tunnel down.
	if _, err := pool.VerifyCertificate(time.Now(), hc); !errors.Is(err, cert.ErrBlockListed) {
		t.Errorf("VerifyCertificate after blocklist = %v, want ErrBlockListed", err)
	}
	if err := pool.VerifyCachedCertificate(time.Now(), cached); !errors.Is(err, cert.ErrBlockListed) {
		t.Errorf("VerifyCachedCertificate after blocklist = %v, want ErrBlockListed", err)
	}
}

// TestNetworkIsolation is the guard rail that survives dropping multi-tenancy.
// Two networks get separate CAs; a certificate from one must not verify against
// the other's pool even though both are structurally valid. That is what makes
// a network a real boundary rather than a label, and it is what CA rotation
// depends on: a pool trusting both CAs accepts either, which is why publishing
// a new CA before promoting it is safe.
func TestNetworkIsolation(t *testing.T) {
	ctx := context.Background()

	// The CA window must strictly contain the host window; nebula rejects a
	// leaf whose NotAfter equals or exceeds the CA's. Give CAs plenty of room.
	netA, _ := testIssuer(t, cert.Curve_CURVE25519, CAParams{
		Name:      "network-a",
		Version:   cert.Version2,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
	})
	netB, _ := testIssuer(t, cert.Curve_CURVE25519, CAParams{
		Name:      "network-b",
		Version:   cert.Version2,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.43.0.0/16")},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
	})

	hcA, err := netA.IssueHost(ctx, hostParams(t, cert.Curve_CURVE25519, "10.42.0.7/16", nil))
	if err != nil {
		t.Fatalf("network A IssueHost: %v", err)
	}

	// Network B's pool must not accept network A's host.
	if _, err := poolFor(t, netB.Certificate()).VerifyCertificate(time.Now(), hcA); err == nil {
		t.Fatal("network B accepted network A's certificate")
	}

	// A pool trusting both (the CA-rotation overlap case) accepts it.
	if _, err := poolFor(t, netA.Certificate(), netB.Certificate()).VerifyCertificate(time.Now(), hcA); err != nil {
		t.Fatalf("combined pool rejected network A cert: %v", err)
	}
}

// TestNewIssuerRejectsMismatchedSigner catches the misconfiguration that would
// otherwise produce certificates failing verification on every peer rather than
// at issuance: CA A's certificate paired with CA B's key.
func TestNewIssuerRejectsMismatchedSigner(t *testing.T) {
	ctx := context.Background()
	issA, _ := testIssuer(t, cert.Curve_CURVE25519, defaultCAParams(t))

	otherPub, otherPriv, err := GenerateCAKey(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatalf("GenerateCAKey: %v", err)
	}
	wrongSigner := NewMemorySigner(cert.Curve_CURVE25519, otherPub, otherPriv)

	if _, err := NewIssuer(ctx, issA.Certificate(), wrongSigner); err == nil {
		t.Fatal("NewIssuer accepted a signer that does not match the CA")
	}
}

// TestNewIssuerRejectsCurveMismatch guards the other half of the same problem.
// nebula returns ErrCurveMismatch at verification time, which surfaces on peers
// rather than here.
func TestNewIssuerRejectsCurveMismatch(t *testing.T) {
	ctx := context.Background()
	iss, _ := testIssuer(t, cert.Curve_CURVE25519, defaultCAParams(t))

	pub, priv, err := GenerateCAKey(cert.Curve_P256)
	if err != nil {
		t.Fatalf("GenerateCAKey: %v", err)
	}

	_, err = NewIssuer(ctx, iss.Certificate(), NewMemorySigner(cert.Curve_P256, pub, priv))
	if !errors.Is(err, ErrCurveMismatch) {
		t.Fatalf("NewIssuer error = %v, want ErrCurveMismatch", err)
	}
}

// TestExpiredCertRejected confirms the time-bound backstop works, which is the
// mechanism revocation falls back on for a partitioned host.
func TestExpiredCertRejected(t *testing.T) {
	ctx := context.Background()
	iss, _ := testIssuer(t, cert.Curve_CURVE25519, defaultCAParams(t))

	// Already expired, but still inside the CA's own validity window so that
	// the only reason for rejection is the leaf's expiry.
	p := hostParams(t, cert.Curve_CURVE25519, "10.42.0.7/16", []string{"web"})
	p.NotBefore = time.Now().Add(-30 * time.Minute)
	p.NotAfter = time.Now().Add(-10 * time.Minute)

	hc, err := iss.IssueHost(ctx, p)
	if err != nil {
		t.Fatalf("IssueHost: %v", err)
	}

	if _, err := poolFor(t, iss.Certificate()).VerifyCertificate(time.Now(), hc); !errors.Is(err, cert.ErrExpired) {
		t.Fatalf("VerifyCertificate = %v, want ErrExpired", err)
	}
}

// TestValidityFor covers the clamping helper. The backdating case is not
// hypothetical: `nebula-cert ca` sets the CA's NotBefore to its creation time,
// so a freshly created CA cannot sign a certificate backdated even one second,
// and every caller that naively subtracts a skew allowance hits it.
func TestValidityFor(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("clamps NotBefore to a freshly created CA", func(t *testing.T) {
		iss, _ := testIssuer(t, cert.Curve_CURVE25519, CAParams{
			Name:      "fresh-ca",
			Version:   cert.Version2,
			Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
			NotBefore: now, // exactly now, as nebula-cert does
			NotAfter:  now.Add(30 * 24 * time.Hour),
		})

		nb, na, err := iss.ValidityFor(24*time.Hour, time.Minute)
		if err != nil {
			t.Fatalf("ValidityFor: %v", err)
		}
		if nb.Before(iss.Certificate().NotBefore()) {
			t.Errorf("NotBefore %s precedes CA NotBefore %s", nb, iss.Certificate().NotBefore())
		}

		// And the result must actually be usable.
		p := hostParams(t, cert.Curve_CURVE25519, "10.42.0.7/16", nil)
		p.NotBefore, p.NotAfter = nb, na
		hc, err := iss.IssueHost(ctx, p)
		if err != nil {
			t.Fatalf("IssueHost with clamped validity: %v", err)
		}
		if _, err := poolFor(t, iss.Certificate()).VerifyCertificate(time.Now(), hc); err != nil {
			t.Fatalf("VerifyCertificate: %v", err)
		}
	})

	t.Run("clamps NotAfter to a soon-expiring CA", func(t *testing.T) {
		iss, _ := testIssuer(t, cert.Curve_CURVE25519, CAParams{
			Name:      "expiring-ca",
			Version:   cert.Version2,
			Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
			NotBefore: now.Add(-time.Hour),
			NotAfter:  now.Add(time.Hour), // shorter than the requested TTL
		})

		_, na, err := iss.ValidityFor(24*time.Hour, time.Minute)
		if err != nil {
			t.Fatalf("ValidityFor: %v", err)
		}
		if na.After(iss.Certificate().NotAfter()) {
			t.Errorf("NotAfter %s exceeds CA NotAfter %s", na, iss.Certificate().NotAfter())
		}
	})

	t.Run("refuses an expired CA", func(t *testing.T) {
		iss, _ := testIssuer(t, cert.Curve_CURVE25519, CAParams{
			Name:      "dead-ca",
			Version:   cert.Version2,
			Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
			NotBefore: now.Add(-2 * time.Hour),
			NotAfter:  now.Add(-time.Hour),
		})

		if _, _, err := iss.ValidityFor(24*time.Hour, time.Minute); !errors.Is(err, ErrOutsideCAValidity) {
			t.Fatalf("ValidityFor on expired CA = %v, want ErrOutsideCAValidity", err)
		}
	})
}

// TestFileSignerMatchesMemorySigner proves the PEM loading path produces an
// identical signer, so `nebula-cert ca` output can be imported into Orbit and
// vice versa.
func TestFileSignerMatchesMemorySigner(t *testing.T) {
	ctx := context.Background()

	for _, curve := range []cert.Curve{cert.Curve_CURVE25519, cert.Curve_P256} {
		t.Run(curve.String(), func(t *testing.T) {
			pub, priv, err := GenerateCAKey(curve)
			if err != nil {
				t.Fatalf("GenerateCAKey: %v", err)
			}

			pemBytes := cert.MarshalSigningPrivateKeyToPEM(curve, priv)
			fs, err := NewFileSignerFromPEM(pemBytes)
			if err != nil {
				t.Fatalf("NewFileSignerFromPEM: %v", err)
			}
			defer fs.Close()

			got, err := fs.Public(ctx)
			if err != nil {
				t.Fatalf("Public: %v", err)
			}
			if string(got) != string(pub) {
				t.Fatalf("FileSigner public key does not match generated key")
			}

			// And it can actually mint a verifiable certificate.
			caCert, err := CreateCA(ctx, fs, defaultCAParams(t))
			if err != nil {
				t.Fatalf("CreateCA: %v", err)
			}
			iss, err := NewIssuer(ctx, caCert, fs)
			if err != nil {
				t.Fatalf("NewIssuer: %v", err)
			}
			hc, err := iss.IssueHost(ctx, hostParams(t, curve, "10.42.0.7/16", []string{"web"}))
			if err != nil {
				t.Fatalf("IssueHost: %v", err)
			}
			if _, err := poolFor(t, caCert).VerifyCertificate(time.Now(), hc); err != nil {
				t.Fatalf("VerifyCertificate: %v", err)
			}
		})
	}
}
