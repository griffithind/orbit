package agent_test

import (
	"context"
	"fmt"
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

// The control plane's RenewAfter.
//
// It was populated by the server and read by nobody, so a fleet-wide
// certificate change — a CA rotation, a compromised signer — waited for every
// host's own midpoint, a median of some seven hours on a day-long certificate.
// The tests below fix the terms on which the agent may honour it: earlier only,
// inside the window only, spread deterministically, and identical to the old
// behaviour when the server has no opinion.

// TestRenewAtWithoutAHintIsUnchanged is the compatibility floor: a zero
// RenewAfter, which is what a server that does not set the field sends, must
// schedule exactly as before.
func TestRenewAtWithoutAHintIsUnchanged(t *testing.T) {
	p := agent.DefaultRenewalPolicy()
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)

	for _, seed := range []string{"host-a", "host-b", "host-c"} {
		want := p.RenewAt(nb, na, seed)
		if got := p.RenewAtWithHint(nb, na, seed, time.Time{}); !got.Equal(want) {
			t.Errorf("seed %s: with a zero hint = %s, want the local schedule %s", seed, got, want)
		}
	}
}

// TestRenewAtHonoursAPullForward is the point of the feature.
func TestRenewAtHonoursAPullForward(t *testing.T) {
	p := agent.DefaultRenewalPolicy()
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)
	hint := nb.Add(time.Hour) // the control plane wants renewal now, not at 12h

	got := p.RenewAtWithHint(nb, na, "host-a", hint)
	if got.Before(hint) {
		t.Errorf("renewal at %s, before the instant the control plane named (%s)", got, hint)
	}
	if !got.Before(hint.Add(p.PullForwardSpread)) {
		t.Errorf("renewal at %s is more than the %s spread past the hint", got, p.PullForwardSpread)
	}
	if local := p.RenewAt(nb, na, "host-a"); !got.Before(local) {
		t.Errorf("renewal at %s did not move earlier than the local schedule %s", got, local)
	}
}

// TestRenewAtHintNeverDelaysRenewal is the safety property that makes the field
// safe to trust at all: a stale, wrong, or hostile control plane must not be
// able to push a host toward expiry by claiming renewal is not due yet.
func TestRenewAtHintNeverDelaysRenewal(t *testing.T) {
	p := agent.DefaultRenewalPolicy()
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)
	local := p.RenewAt(nb, na, "host-a")

	for _, hint := range []time.Time{
		nb.Add(23 * time.Hour), // late in the window
		na.Add(-time.Second),   // the last possible instant
		na.Add(time.Hour),      // past expiry: describes a dead certificate
		na.Add(400 * 24 * time.Hour),
	} {
		got := p.RenewAtWithHint(nb, na, "host-a", hint)
		if !got.Equal(local) {
			t.Errorf("hint %s moved renewal to %s; a hint may only pull renewal earlier "+
				"(local schedule is %s)", hint, got, local)
		}
	}
}

// TestRenewAtHintStaysInsideTheWindow covers the degenerate hints. Renewing
// before NotBefore is meaningless; renewing at or after NotAfter means the host
// dies without ever having tried.
func TestRenewAtHintStaysInsideTheWindow(t *testing.T) {
	p := agent.DefaultRenewalPolicy()
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)

	for _, hint := range []time.Time{
		nb.Add(-time.Hour),
		nb.Add(-365 * 24 * time.Hour),
		time.Unix(0, 0).UTC(),
	} {
		for i := 0; i < 50; i++ {
			seed := string(rune('a'+i%26)) + string(rune('a'+i/26))
			got := p.RenewAtWithHint(nb, na, seed, hint)
			if got.Before(nb) {
				t.Errorf("hint %s scheduled renewal at %s, before NotBefore %s", hint, got, nb)
			}
			if !got.Before(na) {
				t.Errorf("hint %s scheduled renewal at %s, at or after NotAfter %s", hint, got, na)
			}
		}
	}
}

// TestRenewAtHintSpreadsTheFleet is the rate limit. "Renew now" sent to a
// thousand hosts must not become a thousand simultaneous signing requests, and
// the offset must be deterministic so a restarting host does not redraw it.
func TestRenewAtHintSpreadsTheFleet(t *testing.T) {
	p := agent.DefaultRenewalPolicy()
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)
	hint := nb.Add(time.Hour)

	const hosts = 1000
	perSecond := map[int64]int{}
	for i := 0; i < hosts; i++ {
		seed := fmt.Sprintf("host-%04d", i)
		at := p.RenewAtWithHint(nb, na, seed, hint)

		if at.Before(hint) || !at.Before(hint.Add(p.PullForwardSpread)) {
			t.Fatalf("host %s renews at %s, outside [%s, +%s)", seed, at, hint, p.PullForwardSpread)
		}
		if again := p.RenewAtWithHint(nb, na, seed, hint); !again.Equal(at) {
			t.Fatalf("host %s renews at %s then %s; the spread is not deterministic", seed, at, again)
		}
		perSecond[at.Unix()]++
	}

	// A thousand hosts over a minute is about seventeen a second. Ten times that
	// in any one second would mean the spread is not spreading.
	for sec, n := range perSecond {
		if n > 170 {
			t.Errorf("%d of %d hosts renew in the same second (%d); the spread is not bounding the rate",
				n, hosts, sec)
		}
	}
	if len(perSecond) < 30 {
		t.Errorf("a thousand hosts landed in only %d distinct seconds across a %s spread",
			len(perSecond), p.PullForwardSpread)
	}
}

// TestRenewAtIgnoresAHintThatRestatesTheSchedule is the anti-stampede case, and
// the reason the hint is compared against the un-jittered baseline rather than
// against this host's own schedule.
//
// In steady state the server's RenewAfter IS the local baseline: both are the
// certificate's midpoint. Treating that as a pull-forward would collapse an
// hours-wide fleet spread onto one instant plus the pull-forward window — a
// stampede introduced by the mechanism meant to avoid one.
func TestRenewAtIgnoresAHintThatRestatesTheSchedule(t *testing.T) {
	p := agent.DefaultRenewalPolicy()
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)
	midpoint := nb.Add(12 * time.Hour) // what the server sends every day

	seen := map[time.Time]int{}
	for i := 0; i < 200; i++ {
		seed := string(rune('a'+i%26)) + string(rune('a'+i/26))
		got := p.RenewAtWithHint(nb, na, seed, midpoint)
		if want := p.RenewAt(nb, na, seed); !got.Equal(want) {
			t.Fatalf("seed %s: steady-state hint changed the schedule to %s, want %s", seed, got, want)
		}
		seen[got]++
	}
	if len(seen) < 100 {
		t.Errorf("only %d distinct renewal times across 200 hosts; the hint collapsed the fleet spread",
			len(seen))
	}
}

// TestAssessHonoursAPullForward checks the decision the loop actually makes:
// not due on the certificate alone, due once the control plane has asked.
func TestAssessHonoursAPullForward(t *testing.T) {
	p := agent.DefaultRenewalPolicy()
	nb := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)
	hint := nb.Add(time.Hour)
	now := hint.Add(p.PullForwardSpread) // past every host's spread offset

	if got := p.Assess(now, nb, na, "host-a"); got != agent.NotDue {
		t.Fatalf("without a hint, Assess = %v at one hour in, want NotDue", got)
	}
	if got := p.AssessWithHint(now, nb, na, "host-a", hint); got != agent.Due {
		t.Errorf("with a pull-forward hint, Assess = %v, want Due", got)
	}
	// Urgency still describes the certificate, not the server's opinion: a hint
	// must not make a fresh certificate look like one about to expire.
	if got := p.AssessWithHint(na.Add(-time.Minute), nb, na, "host-a", hint); got != agent.Urgent {
		t.Errorf("late in the window with a hint, Assess = %v, want Urgent", got)
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
