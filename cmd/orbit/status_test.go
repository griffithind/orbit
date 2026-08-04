package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/agent"
)

// The status socket reads from goroutines that are still running.
//
// Three of them touch the same state: the tick recording its own outcome, the
// setup loop swapping a network in and out as it retries, and the socket
// answering a request. This is the only concurrent state `orbit status` added,
// and it is in package main — so it needs a test here, and the race job needs
// to cover ./cmd/... for that test to mean anything (see .github/workflows/ci.yml).
//
// The assertion is the race detector. There is nothing to check afterwards:
// either the reads and writes are ordered or they are not.
func TestStatusIsSafeWhileTheAgentRuns(t *testing.T) {
	dir := t.TempDir()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A network loop with nothing behind it. status() reads the state file and
	// the certificate from disk and tolerates both being absent, which is what
	// makes this constructible without a control plane.
	nl := &networkLoop{
		loop:   &agent.Loop{Layout: agent.DefaultLayout(dir), Log: quiet},
		engine: &agent.Embedded{ConfigArg: filepath.Join(dir, "config.yml"), Log: quiet},
		log:    quiet,
	}
	slot := &netSlot{dir: dir}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// The tick, recording when it last ran and what it failed with.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			nl.mu.Lock()
			nl.lastPoll, nl.lastErr = time.Now(), errors.New("control plane unreachable")
			nl.mu.Unlock()
		}
	}()

	// serveNetwork, retrying setup: a network appears, fails, appears again.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			slot.setLoop(nl)
			slot.setError(errors.New("network not ready"))
		}
	}()

	// The socket, answering while all of that happens.
	for i := 0; i < 500; i++ {
		rep := report(context.Background(), dir, []*netSlot{slot})
		if len(rep.Networks) != 1 {
			t.Fatalf("got %d networks, want 1", len(rep.Networks))
		}
	}

	close(stop)
	wg.Wait()
}

// TestAnUnreadyNetworkStillReportsItself. A slot that never got a loop must
// still produce a row, because a host whose network failed to start is the one
// somebody runs this command against.
func TestAnUnreadyNetworkStillReportsItself(t *testing.T) {
	slot := &netSlot{dir: "/var/lib/orbit/staging"}
	slot.setError(errors.New("read agent state: no such file or directory"))

	got := slot.status(context.Background())
	if got.Network != "staging" {
		t.Errorf("network = %q, want staging", got.Network)
	}
	if got.Ready {
		t.Error("a network that never came up reported as ready")
	}
	if got.Error == "" {
		t.Error("the report says the network is not ready and not why")
	}
}

// TestSocketRootFollowsAnExplicitDirectory. A caller that put a network
// somewhere of its own gets the socket beside it — otherwise a test or a
// container binds into a /var/lib/orbit that may not exist.
func TestSocketRootFollowsAnExplicitDirectory(t *testing.T) {
	empty, mode := "", "authoritative"
	none := &dirFlags{dir: &empty, network: &empty, mode: &mode}
	if got := socketRoot(none, "/opt/orbit"); got != "/opt/orbit" {
		t.Errorf("with no -dir, socket root = %q, want the -root value", got)
	}

	explicit := "/tmp/stack/prod"
	df := &dirFlags{dir: &explicit, network: &empty, mode: &mode}
	if got := socketRoot(df, agent.DefaultRoot); got != "/tmp/stack" {
		t.Errorf("with -dir, socket root = %q, want the directory's parent", got)
	}
}
