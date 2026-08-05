package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/fwmatch"
	"github.com/griffithind/orbit/internal/wire"
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
var errNoConfig = errors.New("no verified configuration")

func TestStatusIsSafeWhileTheAgentRuns(t *testing.T) {
	dir := t.TempDir()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A network loop with nothing behind it. status() reads the state file and
	// the certificate from disk and tolerates both being absent, which is what
	// makes this constructible without a control plane.
	nl := &networkLoop{
		loop:   &agent.Loop{Layout: agent.DefaultLayout(dir), Log: quiet},
		engine: &agent.Embedded{Config: func() (string, error) { return "", errNoConfig }, Log: quiet},
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

// TestWhyRendersADenialWithTheNearMisses.
//
// A denial is only useful if it says what nearly matched: a rule that reaches
// this peer on the wrong port is one edit from the answer, and a table with no
// near misses says the peer is not named anywhere. Rendered here because a
// populated firewall on a live host needs a tun device.
func TestWhyRendersADenialWithTheNearMisses(t *testing.T) {
	var buf bytes.Buffer
	prev := out
	out = &buf
	t.Cleanup(func() { out = prev })

	reaches := fwmatch.Rule{Proto: 6, StartPort: 22, EndPort: 22, CIDR: "10.42.0.9/32"}
	printWhy(agent.Explanation{
		Network:      "prod",
		Peer:         "10.42.0.9",
		PeerResolved: "10.42.0.9",
		PeerName:     "db-01",
		PeerKnown:    true,
		PeerGroups:   []string{"env-prod"},
		Proto:        "tcp",
		Port:         "5432",
		Certificate: &agent.CertStatus{
			Name: "web-01", Groups: []string{"env-prod"},
			NotAfter: time.Now().Add(29 * 24 * time.Hour),
		},
		Running:       true,
		TunnelUp:      true,
		CurrentRemote: "203.0.113.7:4242",
		Outbound: fwmatch.Decision{
			Considered: 4,
			Near: []fwmatch.RuleOutcome{
				{Rule: reaches, Outcome: fwmatch.Misses, Reason: "port"},
			},
		},
		Inbound: fwmatch.Decision{
			Considered: 4,
			Matched: []fwmatch.RuleOutcome{{
				Rule:    fwmatch.Rule{Proto: 0, StartPort: 0, EndPort: 0, CIDR: "10.42.0.0/16"},
				Outcome: fwmatch.Matches,
			}},
			Allowed: true,
		},
	})

	got := buf.String()
	t.Log("\n" + got)

	for _, want := range []string{
		"web-01",            // our identity
		"db-01",             // theirs, which we only know because there is a tunnel
		"tunnel up, direct", // the path layer
		"no rule permits",   // the verdict
		"port 22",           // the near miss, so the operator sees what to edit
		"(port)",            // and which term failed
		"allowed by",        // the other direction, which did match
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the explanation is missing %q:\n%s", want, got)
		}
	}
}

// TestWhySaysWhatItCannotDecide. Without a tunnel there is no peer certificate
// here, so a group rule is unevaluable — and reporting that as "denied" would
// be a confident wrong answer in the direction that sends an operator looking
// in the wrong place.
func TestWhySaysWhatItCannotDecide(t *testing.T) {
	var buf bytes.Buffer
	prev := out
	out = &buf
	t.Cleanup(func() { out = prev })

	printWhy(agent.Explanation{
		Network: "prod", PeerResolved: "10.42.0.9", Proto: "tcp", Port: "443",
		PeerKnown: false, Running: true,
		Outbound: fwmatch.Decision{Considered: 2, Undecidable: true},
		Inbound:  fwmatch.Decision{Considered: 2, Undecidable: true},
	})

	got := buf.String()
	if !strings.Contains(got, "cannot be decided") {
		t.Errorf("an undecidable question rendered as something else:\n%s", got)
	}
	if strings.Contains(got, "no rule permits") {
		t.Errorf("an undecidable question rendered as a denial:\n%s", got)
	}
}

// TestReachabilityRendersBothEndsEvenWhenOneSettlesIt.
//
// Which END denies a flow decides whose policy an operator has to change, so a
// bare "DENIED" is not an answer. Both halves print every time.
func TestReachabilityRendersBothEndsEvenWhenOneSettlesIt(t *testing.T) {
	var buf bytes.Buffer
	prev := out
	out = &buf
	t.Cleanup(func() { out = prev })

	printReachability(newRenderer(), wire.ReachabilityResponse{
		Network: "prod",
		Src:     wire.PolicyCheckHost{Name: "web-01", OverlayAddrs: []string{"10.42.0.7"}},
		Dst:     wire.PolicyCheckHost{Name: "db-01", OverlayAddrs: []string{"10.42.0.9"}},
		Proto:   "tcp", Port: "5432",
		FirewallSource: "policy", PolicyVersion: 12,
		Allowed: false,
		Outbound: fwmatch.Decision{
			Considered: 3, Allowed: true,
			Matched: []fwmatch.RuleOutcome{{
				Rule:    fwmatch.Rule{Proto: 6, StartPort: 5432, EndPort: 5432, CIDR: "10.42.0.9/32"},
				Outcome: fwmatch.Matches,
			}},
		},
		Inbound: fwmatch.Decision{
			Considered: 2,
			Near: []fwmatch.RuleOutcome{{
				Rule:    fwmatch.Rule{Proto: 6, StartPort: 443, EndPort: 443, CIDR: "10.42.0.7/32"},
				Outcome: fwmatch.Misses, Reason: "port",
			}},
		},
	})

	got := buf.String()
	t.Log("\n" + got)

	for _, want := range []string{
		"web-01", "db-01", "DENIED",
		"outbound", "allowed by", // the sender permits it
		"inbound", "no rule permits", // and the receiver does not — that is the fix site
		"port 443", // the near miss on the receiver
		"policy version 12",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the answer is missing %q:\n%s", want, got)
		}
	}

	// And it must not imply it knows what the hosts are running.
	if !strings.Contains(got, "stored policy means") {
		t.Errorf("the output does not distinguish configured intent from what is "+
			"actually applied:\n%s", got)
	}
}

// TestSocketRootFollowsAnExplicitDirectory. A caller that put a network
// somewhere of its own gets the socket beside it — otherwise a test or a
// container binds into a /var/lib/orbit that may not exist.
func TestSocketRootFollowsAnExplicitDirectory(t *testing.T) {
	empty := ""
	none := &dirFlags{dir: &empty, network: &empty}
	if got := socketRoot(none, "/opt/orbit"); got != "/opt/orbit" {
		t.Errorf("with no -dir, socket root = %q, want the -root value", got)
	}

	explicit := "/tmp/stack/prod"
	df := &dirFlags{dir: &explicit, network: &empty}
	if got := socketRoot(df, agent.DefaultRoot); got != "/tmp/stack" {
		t.Errorf("with -dir, socket root = %q, want the directory's parent", got)
	}
}
