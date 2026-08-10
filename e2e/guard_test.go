package e2e

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/agent/paths"
)

// The unreachable-guard.
//
// A configuration can be structurally valid, pass nebula's own config test,
// install cleanly, and still sever this host's path back to the control plane —
// a firewall rule that drops the agent port, a lighthouse list that no longer
// resolves. Nothing local detects that at apply time. The only defence is
// noticing sustained loss of contact afterwards and undoing the change.
//
// Without it, one bad push to a fleet is fixed by hand, per host.

// unreachableClient fails every call, standing in for a host that applied a
// config which cut it off.
type unreachableClient struct{ *agent.Client }

func newLoopWithGuard(t *testing.T, host *enrolledHost, baseURL string, g agent.GuardPolicy, now func() time.Time) *agent.Loop {
	t.Helper()
	st, err := agent.ReadState(host.dir)
	if err != nil {
		t.Fatal(err)
	}
	layout := paths.DefaultLayout(host.dir)
	loop := &agent.Loop{
		Client: xffClient(t, baseURL, host.addr),
		Applier: &agent.Applier{
			Layout: layout, Reloader: agent.NoopReloader{},
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		Policy: agent.DefaultRenewalPolicy(),
		Layout: layout,
		Curve:  cert.Curve_P256,
		Guard:  g,
		State:  st,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	// Previously accepted and dropped on the floor, which made every caller's
	// clock argument a lie.
	if now != nil {
		loop.SetClock(now)
	}
	return loop
}

// fakeClock is a hand-advanced time source.
//
// Mutex-guarded because the loop reads the clock from whichever goroutine is
// running a tick, and an unsynchronised variable would trip the race detector
// on a test whose whole purpose is to run under it.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestGuardRevertsUnconfirmedGeneration is the core case: a generation is
// applied, the control plane is never reachable again, and the agent puts the
// previous generation back on its own.
func TestGuardRevertsUnconfirmedGeneration(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "guarded", "10.42.4.5", false, false, nil)

	certPath := paths.DefaultLayout(host.dir).Paths.Cert
	cfgPath := paths.DefaultLayout(host.dir).ConfigPath()
	goodCert := readFile(t, certPath)
	goodCfg := readFile(t, cfgPath)

	loop := newLoopWithGuard(t, host, ts.URL, agent.GuardPolicy{
		ConfirmWithin: 100 * time.Millisecond,
		MinConfirm:    time.Hour, // nothing may confirm during this test
		Quarantine:    time.Hour,
	}, nil)

	// Apply a real new generation (a renewal), which leaves it unconfirmed.
	if err := loop.RenewNow(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	newCert := readFile(t, certPath)
	if newCert == goodCert {
		t.Fatal("renewal did not install a new certificate")
	}

	// The previous generation must have been captured.
	prev := filepath.Join(host.dir, paths.PreviousDirName)
	if _, err := os.Stat(prev); err != nil {
		t.Fatalf("previous generation directory missing: %v", err)
	}

	// Let the confirmation window lapse, then tick. The control plane is
	// reachable here, but MinConfirm is an hour so nothing counts as
	// confirmation — which is exactly the "applied but never proven" state.
	time.Sleep(150 * time.Millisecond)
	_ = loop.Tick(context.Background())

	if got := readFile(t, certPath); got != goodCert {
		t.Error("guard did not restore the previous certificate")
	}
	if got := readFile(t, cfgPath); got != goodCfg {
		t.Error("guard did not restore the previous configuration")
	}
}

// TestGuardQuarantinesTheBadGeneration is what stops revert from becoming a
// loop: revert, poll, get handed the same generation, apply, break again.
func TestGuardQuarantinesTheBadGeneration(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "quarantine", "10.42.4.9", false, false, nil)

	certPath := paths.DefaultLayout(host.dir).Paths.Cert
	goodCert := readFile(t, certPath)

	loop := newLoopWithGuard(t, host, ts.URL, agent.GuardPolicy{
		ConfirmWithin: 50 * time.Millisecond,
		MinConfirm:    time.Hour,
		Quarantine:    time.Hour,
	}, nil)

	if err := loop.RenewNow(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	_ = loop.Tick(context.Background()) // reverts

	if got := readFile(t, certPath); got != goodCert {
		t.Fatal("guard did not revert")
	}

	// Several more ticks. The control plane still advertises the newer epoch,
	// so without quarantine the agent would re-apply it every time.
	for i := 0; i < 3; i++ {
		_ = loop.Tick(context.Background())
	}
	if got := readFile(t, certPath); got != goodCert {
		t.Error("agent re-applied the quarantined generation; revert is looping")
	}
}

// TestGuardDoesNotRevertAConfirmedGeneration is the false-positive check. A
// guard that reverts working configuration is worse than no guard: it turns a
// healthy host on a slow link into a flapping one.
func TestGuardDoesNotRevertAConfirmedGeneration(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "confirmed", "10.42.4.11", false, false, nil)

	certPath := paths.DefaultLayout(host.dir).Paths.Cert

	// Driven, not slept. With a real clock this test asserts that a tick
	// completes within ConfirmWithin, which is a statement about the machine
	// rather than about the guard: under -race it does not, and the test fails
	// having found nothing.
	clock := newFakeClock()
	loop := newLoopWithGuard(t, host, ts.URL, agent.GuardPolicy{
		ConfirmWithin: time.Minute,
		// Not zero: zero means "use the default". A small positive value is
		// how a caller asks for near-immediate confirmation.
		MinConfirm: time.Millisecond,
		Quarantine: time.Hour,
	}, clock.Now)

	if err := loop.RenewNow(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	renewed := readFile(t, certPath)

	// Past MinConfirm, so this tick's success counts as confirmation.
	clock.Advance(time.Second)
	_ = loop.Tick(context.Background())

	// Far past ConfirmWithin. A confirmed generation must survive regardless.
	clock.Advance(time.Hour)
	_ = loop.Tick(context.Background())

	if got := readFile(t, certPath); got != renewed {
		t.Error("guard reverted a generation the control plane had already confirmed")
	}
}

// TestGuardCanBeDisabled covers the escape hatch for deployments where
// something else owns recovery.
func TestGuardDisabled(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "unguarded", "10.42.4.13", false, false, nil)

	certPath := paths.DefaultLayout(host.dir).Paths.Cert

	loop := newLoopWithGuard(t, host, ts.URL, agent.GuardPolicy{
		ConfirmWithin: 10 * time.Millisecond,
		MinConfirm:    time.Hour,
		Disabled:      true,
	}, nil)

	if err := loop.RenewNow(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	renewed := readFile(t, certPath)

	time.Sleep(50 * time.Millisecond)
	_ = loop.Tick(context.Background())

	if got := readFile(t, certPath); got != renewed {
		t.Error("guard reverted despite being disabled")
	}
}

// TestApplyDoesNotLeakBackupDirectories pins the fix for a leak: the previous
// implementation created a fresh temp directory per apply and never removed
// one, so /etc/nebula accumulated a directory for every configuration change
// the host had ever received.
func TestApplyDoesNotLeakBackupDirectories(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "no-leak", "10.42.4.15", false, false, nil)

	loop := newLoopWithGuard(t, host, ts.URL, agent.GuardPolicy{Disabled: true}, nil)
	for i := 0; i < 3; i++ {
		time.Sleep(1100 * time.Millisecond) // distinct certificates
		if err := loop.RenewNow(context.Background()); err != nil {
			t.Fatalf("renew %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(host.dir)
	if err != nil {
		t.Fatal(err)
	}
	var scratch []string
	for _, e := range entries {
		n := e.Name()
		if n == paths.PreviousDirName {
			continue // exactly one, expected
		}
		if len(n) > 6 && n[:7] == ".orbit-" {
			scratch = append(scratch, n)
		}
	}
	if len(scratch) != 0 {
		t.Errorf("apply left %d scratch directories behind: %v", len(scratch), scratch)
	}
}
