package generation

// Supervision tests.
//
// The property under test is narrow and load-bearing: the agent must be able to
// tell a restart that took effect from one that did not. Every one of these
// drives a fake supervisor rather than a real process, so none of them assert
// anything about how fast this machine is. Where a deadline is involved it is a
// deadline the test EXPECTS to expire, which is deterministic in the one
// direction that matters: a slower machine makes the wait longer, never turns a
// failure into a pass.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/agent/dataplane"
	"github.com/griffithind/orbit/internal/agent/paths"
)

// fakeSupervisor is a nebula process the test can start, stop, and replace.
type fakeSupervisor struct {
	mu sync.Mutex

	known    bool
	running  bool
	instance string

	// onRestart replaces the default behaviour of "come back as a new process".
	onRestart func(f *fakeSupervisor) error

	restarts int
}

func newFakeSupervisor() *fakeSupervisor {
	return &fakeSupervisor{known: true, running: true, instance: "run-1"}
}

func (f *fakeSupervisor) Describe() string { return "fake" }

func (f *fakeSupervisor) Status(context.Context) (dataplane.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return dataplane.Status{Known: f.known, Running: f.running, Instance: f.instance, Detail: "fake"}, nil
}

func (f *fakeSupervisor) Restart(context.Context) error {
	f.mu.Lock()
	f.restarts++
	fn := f.onRestart
	f.mu.Unlock()
	if fn != nil {
		return fn(f)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.instance = "run-2"
	f.running = true
	return nil
}

// Ensure starts only when down, and reports whether it did — the contract the
// self-healing path depends on. A supervisor that restarted unconditionally here
// would drop every tunnel on the network once per cycle.
func (f *fakeSupervisor) Ensure(ctx context.Context) (bool, error) {
	f.mu.Lock()
	if !f.known || f.running {
		f.mu.Unlock()
		return false, nil
	}
	f.mu.Unlock()
	return true, f.Restart(ctx)
}

func (f *fakeSupervisor) set(running bool, instance string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running, f.instance = running, instance
}

func testApplier(sup dataplane.Supervisor) *Applier {
	return &Applier{
		Layout:        paths.DefaultLayout("/nonexistent"),
		Reloader:      NoopReloader{},
		Supervisor:    sup,
		RestartSettle: 30 * time.Millisecond,
		RestartPoll:   time.Millisecond,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestRestartIsConfirmedByTheProcessChanging(t *testing.T) {
	f := newFakeSupervisor()
	if err := testApplier(f).restart(context.Background()); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if f.restarts != 1 {
		t.Errorf("restarted %d times, want 1", f.restarts)
	}
}

// TestRestartThatDidNotHappenIsDetected is the whole point of the instance
// token. A service manager that exits zero without replacing the process leaves
// nebula running the OLD certificate; nothing else the agent can observe says
// so, because the old certificate is still valid and the host is still
// reachable at its old address.
func TestRestartThatDidNotHappenIsDetected(t *testing.T) {
	f := newFakeSupervisor()
	f.onRestart = func(*fakeSupervisor) error { return nil } // exits zero, changes nothing

	err := testApplier(f).restart(context.Background())
	if !errors.Is(err, ErrRestartFailed) {
		t.Fatalf("restart error = %v, want ErrRestartFailed", err)
	}
}

// TestRestartThatDoesNotComeBackIsDetected covers the other half: nebula was
// stopped and failed to start again.
func TestRestartThatDoesNotComeBackIsDetected(t *testing.T) {
	f := newFakeSupervisor()
	f.onRestart = func(s *fakeSupervisor) error {
		s.set(false, "")
		return nil
	}

	err := testApplier(f).restart(context.Background())
	if !errors.Is(err, ErrRestartFailed) {
		t.Fatalf("restart error = %v, want ErrRestartFailed", err)
	}
}

// TestRestartCommandFailureIsRestartFailed keeps the two ways a restart can go
// wrong under one sentinel, because the caller's response to both is the same:
// roll back and stop trying.
func TestRestartCommandFailureIsRestartFailed(t *testing.T) {
	f := newFakeSupervisor()
	f.onRestart = func(*fakeSupervisor) error { return errors.New("unit is masked") }

	err := testApplier(f).restart(context.Background())
	if !errors.Is(err, ErrRestartFailed) {
		t.Fatalf("restart error = %v, want ErrRestartFailed", err)
	}
}

// TestUnobservableSupervisorDoesNotFailTheRestart is the escape hatch. A
// hand-rolled restart command with no pidfile cannot be verified; refusing it
// outright would mean such a host can never take an address change at all. It
// is allowed through, loudly, and the log line is the only thing standing
// between the operator and a silent failure.
func TestUnobservableSupervisorDoesNotFailTheRestart(t *testing.T) {
	f := newFakeSupervisor()
	f.known = false
	f.onRestart = func(*fakeSupervisor) error { return nil }

	if err := testApplier(f).restart(context.Background()); err != nil {
		t.Fatalf("restart with an unobservable supervisor: %v", err)
	}
}

// TestLocalizeRewritesWhateverTheServerRendered is the guard against a
// per-network path mismatch.
//
// The previous implementation searched for one hard-coded default. Now that the
// control plane renders a per-network directory, the paths it emits need not
// match any constant this agent holds — so localize reads the values out of the
// config it was handed. A rewrite that missed would leave nebula pointed at
// files nobody wrote.
func TestLocalizeRewritesWhateverTheServerRendered(t *testing.T) {
	a := testApplier(nil)
	a.Layout = paths.DefaultLayout("/opt/orbit/prod")

	got := a.localize("pki:\n  ca: /somewhere/else/entirely/ca.crt\n" +
		"  cert: /somewhere/else/entirely/host.crt\n" +
		"  key: /somewhere/else/entirely/host.key\n")

	want := "pki:\n  ca: /opt/orbit/prod/ca.crt\n" +
		"  cert: /opt/orbit/prod/host.crt\n" +
		"  key: /opt/orbit/prod/host.key\n"
	if got != want {
		t.Errorf("localize gave:\n%s\nwant:\n%s", got, want)
	}
}
