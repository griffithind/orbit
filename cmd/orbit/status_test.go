package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
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

// TestPeersOnANetworkThatNeverStarted.
//
// The host HAS joined it, so this is not a 404: telling an operator the network
// does not exist would send them looking for a typo instead of at the reason it
// is down.
func TestPeersOnANetworkThatNeverStarted(t *testing.T) {
	slot := &netSlot{dir: "/var/lib/orbit/prod"}
	slot.setError(errors.New("read agent state: no such file or directory"))

	rep, err := peerReport(context.Background(), "prod", []*netSlot{slot})
	if err != nil {
		t.Fatalf("a joined network answered with an error: %v", err)
	}
	if rep.Running {
		t.Error("a network that never started reported a running nebula")
	}
	if rep.Detail == "" {
		t.Error("no detail; the report says nothing an operator can act on")
	}
	if rep.Established == nil {
		t.Error("Established is nil, so -json emits null rather than []")
	}
}

// TestPeersOnAnUnjoinedNetworkIs404. The other half: a slug this host has never
// joined is a mistake in the command, not a state of the host.
func TestPeersOnAnUnjoinedNetworkIs404(t *testing.T) {
	slot := &netSlot{dir: "/var/lib/orbit/prod"}

	_, err := peerReport(context.Background(), "staging", []*netSlot{slot})
	if !errors.Is(err, agent.ErrUnknownNetwork) {
		t.Fatalf("got %v, want ErrUnknownNetwork", err)
	}
	if !strings.Contains(err.Error(), "staging") {
		t.Errorf("the error does not name what was asked for: %v", err)
	}
}

// TestPeerTableCarriesWhatAnOperatorNeeds.
//
// Rendered here rather than in the e2e because nebula cannot start without a
// tun device, so no integration test on this machine can produce a populated
// hostmap — and the populated table is the case the command exists for.
func TestPeerTableCarriesWhatAnOperatorNeeds(t *testing.T) {
	var buf bytes.Buffer
	prev := out
	out = &buf
	t.Cleanup(func() { out = prev })

	printPeers(agent.PeerReport{
		Network: "prod",
		Running: true,
		Established: []agent.Peer{
			{
				Name: "db-01", VpnAddrs: []string{"10.42.0.9"},
				CurrentRemote: "203.0.113.7:4242", Messages: 8123,
				CertNotAfter: time.Now().Add(29 * 24 * time.Hour),
			},
			{
				Name: "web-02", VpnAddrs: []string{"10.42.0.8"},
				RelaysToMe: []string{"10.42.0.1"}, Messages: 340,
				CertNotAfter: time.Now().Add(29 * 24 * time.Hour),
			},
		},
		Pending: []agent.Peer{{VpnAddrs: []string{"10.42.0.11"}}},
	})

	got := buf.String()
	t.Log("\n" + got)

	for _, want := range []string{
		"db-01", "10.42.0.9", "203.0.113.7:4242", // a direct tunnel
		"web-02", "relay 10.42.0.1", // and a relayed one, named
		"handshaking", "10.42.0.11", // and one that has not come up
		"2 tunnels, 1 relayed, 1 handshaking",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the table is missing %q:\n%s", want, got)
		}
	}

	// A pending peer has no certificate and so no name; falling back to the
	// address keeps the row readable instead of starting it with a blank.
	if strings.Contains(got, "  ?  ") {
		t.Errorf("a nameless peer rendered as '?' rather than its address:\n%s", got)
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
