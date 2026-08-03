package agent_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/ca"
)

func TestRenewAtMidpoint(t *testing.T) {
	p := agent.RenewalPolicy{Fraction: 0.5} // no jitter
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)

	if got, want := p.RenewAt(nb, na, "host"), nb.Add(12*time.Hour); !got.Equal(want) {
		t.Errorf("RenewAt() = %s, want %s", got, want)
	}
}

// TestRenewAtJitterIsDeterministic is the property that keeps a frequently
// restarting host from renewing far more often than intended: the offset is
// derived from the host id, not from a random source, so it does not move
// between agent restarts.
func TestRenewAtJitterIsDeterministic(t *testing.T) {
	p := agent.DefaultRenewalPolicy()
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)

	first := p.RenewAt(nb, na, "host-a")
	for i := 0; i < 50; i++ {
		if got := p.RenewAt(nb, na, "host-a"); !got.Equal(first) {
			t.Fatalf("RenewAt is not deterministic: %s then %s", first, got)
		}
	}
}

// TestRenewAtJitterSpreadsHosts confirms different hosts land at different
// times. A fleet enrolled together would otherwise renew together forever.
func TestRenewAtJitterSpreadsHosts(t *testing.T) {
	p := agent.DefaultRenewalPolicy()
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)

	seen := map[time.Time]int{}
	for i := 0; i < 200; i++ {
		seen[p.RenewAt(nb, na, string(rune('a'+i%26))+string(rune('a'+i/26)))]++
	}
	if len(seen) < 100 {
		t.Errorf("only %d distinct renewal times across 200 hosts; jitter is not spreading them", len(seen))
	}

	// And every one must stay inside the certificate's window, with margin.
	for at := range seen {
		if at.Before(nb) || !at.Before(na) {
			t.Errorf("renewal time %s falls outside [%s, %s)", at, nb, na)
		}
	}
}

// TestRenewAtClampsToWindow covers the degenerate inputs. A renewal scheduled
// after expiry means the host silently dies without ever having tried.
func TestRenewAtClampsToWindow(t *testing.T) {
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(time.Hour)

	for _, p := range []agent.RenewalPolicy{
		{Fraction: 0.99, Jitter: 0.5}, // jitter could push past NotAfter
		{Fraction: 0.01, Jitter: 0.5}, // jitter could push before NotBefore
		{Fraction: 2.0},               // nonsense fraction
	} {
		at := p.RenewAt(nb, na, "host")
		if at.Before(nb) {
			t.Errorf("policy %+v scheduled renewal before NotBefore", p)
		}
		if !at.Before(na) {
			t.Errorf("policy %+v scheduled renewal at or after NotAfter", p)
		}
	}
}

func TestAssessUrgency(t *testing.T) {
	p := agent.RenewalPolicy{Fraction: 0.5}
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)

	tests := []struct {
		name string
		now  time.Time
		want agent.Urgency
	}{
		{"fresh", nb.Add(time.Hour), agent.NotDue},
		{"just before midpoint", nb.Add(11 * time.Hour), agent.NotDue},
		{"at midpoint", nb.Add(12 * time.Hour), agent.Due},
		{"three quarters", nb.Add(18 * time.Hour), agent.Urgent},
		{"expired", na.Add(time.Minute), agent.Expired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Assess(tc.now, nb, na, "host"); got != tc.want {
				t.Errorf("Assess = %v, want %v", got, tc.want)
			}
		})
	}
}

// issueCert mints a certificate for testing ModeFor.
func issueCert(t *testing.T, addr string, curve cert.Curve) string {
	t.Helper()
	ctx := context.Background()

	pub, priv, err := ca.GenerateCAKey(curve)
	if err != nil {
		t.Fatal(err)
	}
	signer := ca.NewMemorySigner(curve, pub, priv)

	now := time.Now()
	caCert, err := ca.CreateCA(ctx, signer, ca.CAParams{
		Name:      "mode-test",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	iss, err := ca.NewIssuer(ctx, caCert, signer)
	if err != nil {
		t.Fatal(err)
	}

	hostPub, _, err := ca.GenerateHostKey(curve)
	if err != nil {
		t.Fatal(err)
	}
	nb, na, err := iss.ValidityFor(24*time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := iss.IssueHost(ctx, ca.HostParams{
		Name:      "h",
		Networks:  []netip.Prefix{netip.MustParsePrefix(addr)},
		PublicKey: hostPub,
		NotBefore: nb, NotAfter: na,
	})
	if err != nil {
		t.Fatal(err)
	}
	pem, err := c.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	return string(pem)
}

// TestModeFor is the guard against the silent failure described in the doc
// comment: nebula rejects a reload whose certificate networks changed, logs an
// error, and keeps running on the old certificate until it expires. The host
// then drops off the mesh for reasons that look nothing like "its address
// changed".
func TestModeFor(t *testing.T) {
	a := issueCert(t, "10.42.0.7/16", cert.Curve_CURVE25519)
	sameAddr := issueCert(t, "10.42.0.7/16", cert.Curve_CURVE25519)
	otherAddr := issueCert(t, "10.42.0.8/16", cert.Curve_CURVE25519)
	otherCurve := issueCert(t, "10.42.0.7/16", cert.Curve_P256)

	tests := []struct {
		name    string
		current string
		next    string
		want    agent.ApplyMode
	}{
		{"first enrollment", "", a, agent.ModeReload},
		{"routine renewal", a, sameAddr, agent.ModeReload},
		{"address changed", a, otherAddr, agent.ModeRestart},
		{"curve changed", a, otherCurve, agent.ModeRestart},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := agent.ModeFor(tc.current, tc.next)
			if err != nil {
				t.Fatalf("ModeFor: %v", err)
			}
			if got != tc.want {
				t.Errorf("ModeFor = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCertificateWindow(t *testing.T) {
	pem := issueCert(t, "10.42.0.7/16", cert.Curve_CURVE25519)
	nb, na, err := agent.CertificateWindow(pem)
	if err != nil {
		t.Fatalf("CertificateWindow: %v", err)
	}
	if !na.After(nb) {
		t.Errorf("window is inverted: %s to %s", nb, na)
	}
	if d := na.Sub(nb); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("window is %s, want about 24h", d)
	}
}

func TestKeypairFromPrivateRoundTrips(t *testing.T) {
	for _, curve := range []cert.Curve{cert.Curve_CURVE25519, cert.Curve_P256} {
		t.Run(curve.String(), func(t *testing.T) {
			kp, err := agent.GenerateKeypair(curve)
			if err != nil {
				t.Fatal(err)
			}
			raw, _, gotCurve, err := cert.UnmarshalPrivateKeyFromPEM([]byte(kp.PrivatePEM))
			if err != nil {
				t.Fatal(err)
			}
			if gotCurve != curve {
				t.Fatalf("curve = %v, want %v", gotCurve, curve)
			}

			// Reusing the key must derive the same public half, or a
			// --reuse-key renewal would mint a certificate for a key the host
			// does not hold.
			again, err := agent.KeypairFromPrivate(curve, raw)
			if err != nil {
				t.Fatal(err)
			}
			if again.PublicB64 != kp.PublicB64 {
				t.Errorf("derived public key differs from the generated one")
			}
		})
	}
}
