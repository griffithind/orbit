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

func (f *fakeSupervisor) Status(context.Context) (Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Status{Known: f.known, Running: f.running, Instance: f.instance, Detail: "fake"}, nil
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

func (f *fakeSupervisor) set(running bool, instance string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running, f.instance = running, instance
}

func testApplier(sup Supervisor) *Applier {
	return &Applier{
		Layout:        DefaultLayout("/nonexistent"),
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

func TestValidateNetwork(t *testing.T) {
	for _, ok := range []string{"prod", "a", "staging-2", "0123456789012345678901234567890a"} {
		if err := ValidateNetwork(ok); err != nil {
			t.Errorf("ValidateNetwork(%q) = %v, want nil", ok, err)
		}
	}
	// "." and ".." escape the root, "/" escapes it further, and uppercase or
	// "@" would confuse a systemd instance name.
	for _, bad := range []string{"", ".", "..", "a/b", "Prod", "pro_d", "net@1",
		"01234567890123456789012345678901x"} {
		if err := ValidateNetwork(bad); err == nil {
			t.Errorf("ValidateNetwork(%q) = nil, want an error", bad)
		}
	}
}

// TestLayoutModes pins the contract the control-plane renderer and the systemd
// units are both written against.
func TestLayoutModes(t *testing.T) {
	auth := DefaultLayout("/var/lib/orbit/prod")
	if got := auth.ConfigPath(); got != "/var/lib/orbit/prod/nebula.yml" {
		t.Errorf("authoritative config = %q", got)
	}
	// The FILE, not a directory: pointing nebula at a directory is what brings
	// the merge back.
	if got := auth.NebulaConfigArg(); got != "/var/lib/orbit/prod/nebula.yml" {
		t.Errorf("authoritative -config = %q", got)
	}
	if auth.Network != "prod" {
		t.Errorf("network = %q, want prod", auth.Network)
	}
	if got := auth.StatePath(); got != "/var/lib/orbit/prod/agent.json" {
		t.Errorf("state path = %q", got)
	}
	if got := auth.PreviousDir(); got != "/var/lib/orbit/prod/.previous" {
		t.Errorf("previous dir = %q", got)
	}

	frag := FragmentLayout("/var/lib/orbit/prod")
	if got := frag.ConfigPath(); got != "/var/lib/orbit/prod/config.d/50-orbit.yml" {
		t.Errorf("fragment config = %q", got)
	}
	if got := frag.NebulaConfigArg(); got != "/var/lib/orbit/prod/config.d" {
		t.Errorf("fragment -config = %q, want the directory", got)
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
	a.Layout = DefaultLayout("/opt/orbit/prod")

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

func loopWithSupervisor(t *testing.T, sup Supervisor) *Loop {
	t.Helper()
	dir := t.TempDir()
	layout := DefaultLayout(dir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Loop{
		Applier: &Applier{Layout: layout, Reloader: NoopReloader{}, Supervisor: sup, Log: log},
		Layout:  layout,
		State:   State{BaseURL: "http://control.invalid", HostID: "h"},
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

	l.quarantineEpoch(42, ErrRestartFailed)
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
	if undeliverable(errors.New(ErrRestartRequired.Error())) {
		t.Error("undeliverable matched on the message rather than the error")
	}
	if !undeliverable(errors.Join(ErrRestartFailed, errors.New("x"))) {
		t.Error("a wrapped ErrRestartFailed was not classified as undeliverable")
	}
	if !undeliverable(errors.Join(ErrRestartRequired, errors.New("x"))) {
		t.Error("a wrapped ErrRestartRequired was not classified as undeliverable")
	}
	if undeliverable(errors.New("connection refused")) {
		t.Error("an ordinary error was classified as undeliverable")
	}
}
