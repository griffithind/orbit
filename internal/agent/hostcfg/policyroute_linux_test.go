package hostcfg

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// These need root and a real kernel, so they skip by default and run in the container
// `make test-netns` starts. They are here rather than in e2e because what they prove is
// not about Orbit's protocol at all: it is that the two objects this file installs
// actually divert marked traffic. That was assumed once already and was false.
func requireNetAdmin(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root and its own network namespace; run: make test-netns")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2")
	}
}

// exitRouteWorld builds what a host looks like once nebula has installed an exit route:
// a tun device carrying the two halves of a default route, with the physical default
// still in place underneath.
func exitRouteWorld(t *testing.T) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	run("link", "add", "tun0", "type", "dummy")
	run("addr", "add", "10.42.0.1/24", "dev", "tun0")
	run("link", "set", "tun0", "up")
	run("route", "add", "0.0.0.0/1", "dev", "tun0")
	run("route", "add", "128.0.0.0/1", "dev", "tun0")
	t.Cleanup(func() {
		removePolicyRoute()
		exec.Command("ip", "link", "del", "tun0").Run()
	})
}

func routeFor(t *testing.T, dst string, mark string) string {
	t.Helper()
	args := []string{"route", "get", dst}
	if mark != "" {
		args = append(args, "mark", mark)
	}
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// TestPolicyRouteDivertsMarkedTraffic is the whole claim: nebula's own UDP, which carries
// the mark, leaves by the physical interface, while everything else goes into the tunnel.
// Without the rule both take the tunnel and the machine falls off the network.
func TestPolicyRouteDivertsMarkedTraffic(t *testing.T) {
	requireNetAdmin(t)
	exitRouteWorld(t)

	// Before: the mark buys nothing, which is the bug this file fixes.
	if got := routeFor(t, "1.1.1.1", "0x4242"); !strings.Contains(got, "tun0") {
		t.Fatalf("precondition failed, marked traffic already avoids the tunnel: %s", got)
	}

	h := HostState{ExitNode: true, SoMark: 0x4242, TunDev: "tun0"}
	if err := applyPolicyRoute(h); err != nil {
		t.Fatalf("applyPolicyRoute: %v", err)
	}

	if got := routeFor(t, "1.1.1.1", "0x4242"); strings.Contains(got, "tun0") {
		t.Errorf("marked traffic still goes into the tunnel:\n%s", got)
	}
	if got := routeFor(t, "1.1.1.1", ""); !strings.Contains(got, "tun0") {
		t.Errorf("unmarked traffic should take the exit route but did not:\n%s", got)
	}
}

// TestPolicyRouteIsIdempotent guards the reconcile loop: this runs every cycle, and a
// version that added a rule each time would bury the machine in them.
func TestPolicyRouteIsIdempotent(t *testing.T) {
	requireNetAdmin(t)
	exitRouteWorld(t)

	h := HostState{ExitNode: true, SoMark: 0x4242, TunDev: "tun0"}
	for i := 0; i < 3; i++ {
		if err := applyPolicyRoute(h); err != nil {
			t.Fatalf("applyPolicyRoute %d: %v", i, err)
		}
	}

	out, err := exec.Command("ip", "-4", "rule", "show", "priority", "4242").CombinedOutput()
	if err != nil {
		t.Fatalf("ip rule show: %v: %s", err, out)
	}
	if n := len(strings.Fields(strings.TrimSpace(string(out)))); n == 0 {
		t.Fatal("no rule installed")
	}
	if n := strings.Count(string(out), "fwmark"); n != 1 {
		t.Errorf("want exactly 1 rule after 3 applies, got %d:\n%s", n, out)
	}
}

// TestPolicyRouteRemoves proves uninstall leaves nothing behind, including after the
// rules were changed by somebody else — the same ownership property the nftables table
// has, checked the same way.
func TestPolicyRouteRemoves(t *testing.T) {
	requireNetAdmin(t)
	exitRouteWorld(t)

	h := HostState{ExitNode: true, SoMark: 0x4242, TunDev: "tun0"}
	if err := applyPolicyRoute(h); err != nil {
		t.Fatalf("applyPolicyRoute: %v", err)
	}
	// Somebody edits our table.
	exec.Command("ip", "route", "add", "10.99.0.0/16", "dev", "tun0", "table", "4242").Run()

	if err := removePolicyRoute(); err != nil {
		t.Fatalf("removePolicyRoute: %v", err)
	}

	out, _ := exec.Command("ip", "-4", "rule", "show", "priority", "4242").CombinedOutput()
	if strings.Contains(string(out), "fwmark") {
		t.Errorf("rule survived removal:\n%s", out)
	}
	out, _ = exec.Command("ip", "route", "show", "table", "4242").CombinedOutput()
	if strings.TrimSpace(string(out)) != "" {
		t.Errorf("table survived removal:\n%s", out)
	}
	// And the machine is back to where it started.
	if got := routeFor(t, "1.1.1.1", "0x4242"); !strings.Contains(got, "tun0") {
		t.Errorf("removal did not restore the previous routing:\n%s", got)
	}
}

// TestPolicyRouteRemovedWhenNotAnExitNode covers the withdrawal path: a machine that
// stops using an exit node must stop diverting, or it keeps sending nebula's traffic
// somewhere the control plane no longer believes in.
func TestPolicyRouteRemovedWhenNotAnExitNode(t *testing.T) {
	requireNetAdmin(t)
	exitRouteWorld(t)

	if err := applyPolicyRoute(HostState{ExitNode: true, SoMark: 0x4242, TunDev: "tun0"}); err != nil {
		t.Fatalf("applyPolicyRoute: %v", err)
	}
	if err := applyPolicyRoute(HostState{TunDev: "tun0"}); err != nil {
		t.Fatalf("applyPolicyRoute (withdrawn): %v", err)
	}

	out, _ := exec.Command("ip", "-4", "rule", "show", "priority", "4242").CombinedOutput()
	if strings.Contains(string(out), "fwmark") {
		t.Errorf("rule survived the withdrawal:\n%s", out)
	}
}
