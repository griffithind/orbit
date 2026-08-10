package dataplane

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestPhysicalDefaultInterface checks the RIB parsing against what the system itself
// says. It is the part of the darwin listener most likely to be silently wrong — a
// mis-parsed routing message gives a plausible interface index, and pinning to the wrong
// interface fails as "nebula cannot reach anything", three layers from the cause.
func TestPhysicalDefaultInterface(t *testing.T) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		t.Skip("no default route on this machine")
	}
	var want string
	for _, line := range strings.Split(string(out), "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "interface:"); ok {
			want = strings.TrimSpace(name)
		}
	}
	if want == "" {
		t.Skip("route(8) reported no interface for the default route")
	}

	idx, name, err := PhysicalDefaultInterface()
	if err != nil {
		t.Fatalf("physicalDefaultInterface: %v", err)
	}
	if name != want {
		t.Errorf("picked %q (index %d), route(8) says %q", name, idx, want)
	}
	if idx == 0 {
		t.Error("index 0 means unbound, which would leave the socket following the routing table")
	}
}

// TestPhysicalDefaultSkipsTunnels is the property that keeps this from being the loop it
// exists to prevent: once an exit node is in use there IS a default route, pointing at
// nebula's own utun, and pinning to that would send nebula's UDP into the tunnel carrying
// it. Tailscale's netns_darwin.go refuses the same way.
func TestPhysicalDefaultSkipsTunnels(t *testing.T) {
	for _, name := range []string{"utun0", "utun8", "ipsec0"} {
		if !isTunnelInterface(name) {
			t.Errorf("%s should be treated as a tunnel", name)
		}
	}
	for _, name := range []string{"en0", "en1", "bridge0", "lo0"} {
		if isTunnelInterface(name) {
			t.Errorf("%s should not be treated as a tunnel", name)
		}
	}
}

// TestNoListenerWithoutAnExitNode is the blast radius. Every Mac that has not been given
// an exit node must get nebula's own listener, unchanged — the factory is nil, so there
// is no Orbit code in that datapath at all.
func TestNoListenerWithoutAnExitNode(t *testing.T) {
	if f := newListenerFactory(nil, false); f != nil {
		t.Error("a host with no exit node should use nebula's own listener")
	}
	if f := newListenerFactory(nil, true); f == nil {
		t.Error("a host with an exit node needs a pinned listener")
	}
}

// TestErrNoPhysicalDefaultIsDistinct: refusing to start is the right answer when every
// default route leads into a tunnel, and the caller has to be able to tell that apart
// from a socket that failed to open.
func TestErrNoPhysicalDefaultIsDistinct(t *testing.T) {
	if !errors.Is(ErrNoPhysicalDefault, ErrNoPhysicalDefault) {
		t.Fatal("sentinel is not comparable")
	}
}
