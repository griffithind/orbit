package agent

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
	"github.com/griffithind/orbit/internal/agent/generation"
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

func testApplier(sup dataplane.Supervisor) *generation.Applier {
	return &generation.Applier{
		Layout:        paths.DefaultLayout("/nonexistent"),
		Reloader:      generation.NoopReloader{},
		Supervisor:    sup,
		RestartSettle: 30 * time.Millisecond,
		RestartPoll:   time.Millisecond,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func loopWithSupervisor(t *testing.T, sup dataplane.Supervisor) *Loop {
	t.Helper()
	dir := t.TempDir()
	layout := paths.DefaultLayout(dir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Loop{
		Applier: &generation.Applier{Layout: layout, Reloader: generation.NoopReloader{}, Supervisor: sup, Log: log},
		Layout:  layout,
		State:   State{BaseURL: "http://control.invalid", MembershipID: "h"},
		Log:     log,
	}
}

// TestNebulaNotRunningIsRecordedAndPersisted is the liveness half of
// supervision. A host whose data plane will not start reports converged epochs
// and is off the mesh; before this the agent could not tell the difference
// either.
func TestNebulaNotRunningIsRecordedAndPersisted(t *testing.T) {
	f := newFakeSupervisor()
	l := loopWithSupervisor(t, f)
	clock := time.Now()
	l.SetClock(func() time.Time { return clock })

	f.set(false, "")
	l.checkDataPlane(context.Background())
	if l.State.DataPlaneDownSince.IsZero() {
		t.Fatal("nebula being down was not recorded")
	}
	first := l.State.DataPlaneDownSince

	// Persisted, so an agent restart does not reset the clock on the outage and
	// report a fresh one-second problem instead of an hour-old one.
	persisted, err := ReadState(l.Layout.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.DataPlaneDownSince.Equal(first) {
		t.Errorf("persisted %v, in memory %v", persisted.DataPlaneDownSince, first)
	}

	// Still down later: the ORIGINAL time survives, or the reported duration is
	// "since the last poll" rather than "since it broke".
	clock = clock.Add(time.Hour)
	l.checkDataPlane(context.Background())
	if !l.State.DataPlaneDownSince.Equal(first) {
		t.Errorf("down-since moved to %v, want %v", l.State.DataPlaneDownSince, first)
	}

	f.set(true, "run-9")
	l.checkDataPlane(context.Background())
	if !l.State.DataPlaneDownSince.IsZero() {
		t.Error("recovery did not clear the down marker")
	}
}

// TestUnobservableNebulaIsNotReportedDown is the false-positive check, and it
// matters more than it looks: reporting every host with a hand-rolled reloader
// as down would make the signal worthless on the day it is real.
func TestUnobservableNebulaIsNotReportedDown(t *testing.T) {
	f := newFakeSupervisor()
	f.known = false
	l := loopWithSupervisor(t, f)

	l.checkDataPlane(context.Background())
	if !l.State.DataPlaneDownSince.IsZero() {
		t.Error("an unobservable nebula was reported as down")
	}

	// And with no supervisor at all.
	l2 := loopWithSupervisor(t, nil)
	l2.checkDataPlane(context.Background())
	if !l2.State.DataPlaneDownSince.IsZero() {
		t.Error("a host with no supervisor was reported as down")
	}
}

// TestQuarantineStopsRepeatedRestarts is the pacing guard. A generation that
// needs a restart this host cannot deliver will be offered again on the very
// next poll; without a quarantine the agent tries forever, and in the
// restart-failed case each attempt drops every tunnel on the network.
func TestQuarantineStopsRepeatedRestarts(t *testing.T) {
	l := loopWithSupervisor(t, nil)
	clock := time.Now()
	l.SetClock(func() time.Time { return clock })

	l.quarantineEpoch(42, generation.ErrRestartFailed)
	if !l.quarantined(42) {
		t.Fatal("the failed generation was not quarantined")
	}
	if l.quarantined(43) {
		t.Error("quarantine leaked to a different generation")
	}

	// It expires, having given an operator time to look.
	clock = clock.Add(l.guard().Quarantine + time.Second)
	if l.quarantined(42) {
		t.Error("quarantine never expired")
	}
}

// TestUndeliverableClassifiesBothSentinels pins what the loop keys its
// quarantine off. Misclassifying either turns a permanent condition into a
// restart every poll interval, and a restart drops every tunnel on the network.
func TestUndeliverableClassifiesBothSentinels(t *testing.T) {
	// A message that merely reads like the sentinel is not the sentinel.
	if undeliverable(errors.New(generation.ErrRestartRequired.Error())) {
		t.Error("undeliverable matched on the message rather than the error")
	}
	if !undeliverable(errors.Join(generation.ErrRestartFailed, errors.New("x"))) {
		t.Error("a wrapped generation.ErrRestartFailed was not classified as undeliverable")
	}
	if !undeliverable(errors.Join(generation.ErrRestartRequired, errors.New("x"))) {
		t.Error("a wrapped generation.ErrRestartRequired was not classified as undeliverable")
	}
	if undeliverable(errors.New("connection refused")) {
		t.Error("an ordinary error was classified as undeliverable")
	}
}
