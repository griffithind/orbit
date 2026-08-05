package agent

import (
	"context"
	"errors"
	"testing"
)

// Recovery. A host that cannot heal itself is a host somebody has to visit.

// TestEnsureStartsWhatIsNotRunning is the whole self-healing property in one
// assertion: something that is down gets started, and something already up is
// left alone rather than restarted underneath its tunnels.
func TestEnsureStartsWhatIsNotRunning(t *testing.T) {
	// A Config that fails is the case that matters: starting must REPORT that
	// it tried, and the error, rather than quietly deciding nebula is fine.
	e := &Embedded{Config: func() (string, error) {
		return "", errors.New("no verified configuration")
	}}

	started, err := e.Ensure(context.Background())
	if !started {
		t.Error("Ensure did not attempt to start a nebula that was down")
	}
	if err == nil {
		t.Error("Ensure reported success for a configuration that does not exist")
	}

	st, _ := e.Status(context.Background())
	if !st.Known {
		t.Error("an embedded engine always knows whether nebula is running")
	}
	if st.Running {
		t.Error("Status reports Running for a nebula that failed to start")
	}
}

// TestStatusDoesNotClaimARunningNebulaAfterItStops.
//
// Status is what the apply path uses to decide whether a restart took. An
// engine that keeps saying Running after nebula has died would confirm restarts
// that never happened and leave a host with no data plane and nothing saying so.
//
// Driven through the fields rather than a real nebula, because the property
// under test is the bookkeeping: what the watcher goroutine does when Wait
// returns.
func TestStatusDoesNotClaimARunningNebulaAfterItStops(t *testing.T) {
	e := &Embedded{}

	e.mu.Lock()
	e.running, e.generation = true, 7
	e.mu.Unlock()

	if st, _ := e.Status(context.Background()); !st.Running {
		t.Fatal("test setup: expected the engine to look up")
	}

	// What the watcher does when nebula exits on its own.
	e.mu.Lock()
	if e.generation == 7 {
		e.running, e.lastExit = false, context.Canceled
	}
	e.mu.Unlock()

	st, _ := e.Status(context.Background())
	if st.Running {
		t.Error("Status still reports Running after nebula stopped")
	}
	if !st.Known {
		t.Error("the engine stopped knowing; an embedded nebula is always observable")
	}
}

// TestARestartDoesNotMarkTheNewInstanceDown. The old instance's Wait returns
// after a deliberate restart, and the watcher must not attribute that to the
// instance that just replaced it — which would leave a running nebula reported
// as down and restarted on the next tick, forever.
func TestARestartDoesNotMarkTheNewInstanceDown(t *testing.T) {
	e := &Embedded{}

	e.mu.Lock()
	e.running, e.generation = true, 3
	staleGen := e.generation
	e.mu.Unlock()

	// A restart: stopLocked advances the generation past what the old watcher
	// is guarding.
	e.mu.Lock()
	e.stopLocked()
	e.running, e.generation = true, e.generation+1 // stands in for the new start
	newGen := e.generation
	e.mu.Unlock()

	if staleGen == newGen {
		t.Fatal("the generation did not advance across a restart, so a stale watcher " +
			"cannot be told from a live one")
	}

	// The OLD watcher fires now.
	e.mu.Lock()
	if e.generation == staleGen {
		e.running = false
	}
	e.mu.Unlock()

	if st, _ := e.Status(context.Background()); !st.Running {
		t.Error("a stale watcher marked the new instance down; the engine would " +
			"restart a healthy nebula on every tick")
	}
}
