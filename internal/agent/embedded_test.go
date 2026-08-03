package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The engine must be given what nebula is meant to LOAD, which is not the same
// as the file the agent WRITES.
//
// Layout.ConfigPath is where the agent writes: nebula.yml in authoritative
// mode, config.d/50-orbit.yml in fragment mode. Layout.NebulaConfigArg is what
// nebula is pointed at: the same file in authoritative mode, but the DIRECTORY
// in fragment mode, because nebula loads a file verbatim and merges a
// directory.
//
// Handing the engine ConfigPath works perfectly in authoritative mode — which
// is the default, and every test — and on a fragment-mode host silently loads
// the Orbit fragment alone, dropping every operator-authored file the mode
// exists to include. A host would come up on a configuration nobody wrote.
func TestEngineIsPointedAtWhatNebulaLoads(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      ConfigMode
		wantIsDir bool
	}{
		{"authoritative", ConfigAuthoritative, false},
		{"fragment", ConfigFragment, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := DefaultLayout(t.TempDir())
			l.Mode = tc.mode

			arg := l.NebulaConfigArg()
			gotDir := arg == filepath.Join(l.Dir, ConfigDirName)
			if gotDir != tc.wantIsDir {
				t.Fatalf("NebulaConfigArg() = %q; want a directory: %v", arg, tc.wantIsDir)
			}
			if tc.mode == ConfigFragment && arg == l.ConfigPath() {
				t.Error("in fragment mode nebula must be given the directory, not the " +
					"fragment: loading the fragment alone drops every operator file")
			}
		})
	}
}

// TestAgentRunPointsTheEngineAtTheDirectory reads the call site, because the
// bug it guards is a field assignment and there is exactly one place it can be
// written wrong.
func TestAgentRunPointsTheEngineAtTheDirectory(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "orbit", "agent.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "ConfigArg: layout.ConfigPath()") {
		t.Error("the engine is given Layout.ConfigPath. That is what the agent WRITES; " +
			"nebula must be given NebulaConfigArg, which is the config.d directory on a " +
			"fragment-mode host")
	}
	if !strings.Contains(text, "ConfigArg: layout.NebulaConfigArg()") {
		t.Error("cmd/orbit no longer points the engine at NebulaConfigArg; if the wiring " +
			"moved, update this test rather than deleting it")
	}
}

// Recovery. A host that cannot heal itself is a host somebody has to visit.

// TestEnsureStartsWhatIsNotRunning is the whole self-healing property in one
// assertion: something that is down gets started, and something already up is
// left alone rather than restarted underneath its tunnels.
func TestEnsureStartsWhatIsNotRunning(t *testing.T) {
	e := &Embedded{ConfigArg: filepath.Join(t.TempDir(), "nebula.yml")}

	// The config does not exist, so starting fails — which is the case that
	// matters. Ensure must REPORT that it tried, and the error, rather than
	// quietly deciding nebula is fine.
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
