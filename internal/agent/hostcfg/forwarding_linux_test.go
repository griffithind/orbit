package hostcfg

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

// A packet actually crossing a gateway, which nothing in this repository has
// ever asserted.
//
// The e2e suite covers gateways thoroughly at the level of INTENT — rendered
// YAML and stored state — and stops there. Every defect ADR-0034 records
// renders correctly: the MSS clamp was absent rather than wrong, masquerade
// defaulted off for a route that cannot work without it, and a `/0` NAT rule
// matched a sibling prefix that had asked for none. Assertions on the ruleset
// catch a rule that is missing or misscoped; only a packet catches the rest.
//
// The topology, all in one machine's namespaces:
//
//	client ns ──veth── [ gateway = the test's own ns ] ──veth── server ns
//	 10.42.0.2          10.42.0.1        192.168.88.1        192.168.88.2
//
// The left veth stands in for the overlay: it is what HostState.TunDev names, so
// the rules under test are scoped to it exactly as they would be to a tun.

func ipRun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func inNS(t *testing.T, ns string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...).CombinedOutput()
	return string(out), err
}

// gatewayWorld builds the topology above and returns nothing: every address in
// it is fixed, because a test that computes its own addresses is a test that
// can disagree with its own assertions.
func gatewayWorld(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("needs nftables")
	}

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", "cli").Run()
		_ = exec.Command("ip", "netns", "del", "srv").Run()
		_ = exec.Command("ip", "link", "del", "gw-cli").Run()
		_ = exec.Command("ip", "link", "del", "gw-srv").Run()
		_ = (&nftConfigurer{}).removeTable()
		_ = setForwarding(false)
	})

	ipRun(t, "netns", "add", "cli")
	ipRun(t, "netns", "add", "srv")

	// Client side. gw-cli is the gateway's end and stands in for the tun.
	ipRun(t, "link", "add", "gw-cli", "type", "veth", "peer", "name", "eth0", "netns", "cli")
	ipRun(t, "addr", "add", "10.42.0.1/24", "dev", "gw-cli")
	ipRun(t, "link", "set", "gw-cli", "up")
	ipRun(t, "-n", "cli", "addr", "add", "10.42.0.2/24", "dev", "eth0")
	ipRun(t, "-n", "cli", "link", "set", "eth0", "up")
	ipRun(t, "-n", "cli", "route", "add", "default", "via", "10.42.0.1")

	// Server side: the "LAN" behind the gateway.
	ipRun(t, "link", "add", "gw-srv", "type", "veth", "peer", "name", "eth0", "netns", "srv")
	ipRun(t, "addr", "add", "192.168.88.1/24", "dev", "gw-srv")
	ipRun(t, "link", "set", "gw-srv", "up")
	ipRun(t, "-n", "srv", "addr", "add", "192.168.88.2/24", "dev", "eth0")
	ipRun(t, "-n", "srv", "link", "set", "eth0", "up")

	// Deliberately NO route back to 10.42.0.0/24 on the server. That is the
	// whole point of masquerade: a LAN host does not know the overlay exists,
	// and a gateway that does not NAT is a gateway whose replies never return.
}

// TestGatewayForwardsAPacket is the assertion the suite never made.
func TestGatewayForwardsAPacket(t *testing.T) {
	requireNetAdmin(t)
	gatewayWorld(t)

	lan := netip.MustParsePrefix("192.168.88.0/24")
	h := HostState{
		TunDev:     "gw-cli",
		Forward:    true,
		Masquerade: []netip.Prefix{lan},
	}
	if err := (&nftConfigurer{network: "test"}).Apply(h); err != nil {
		t.Fatalf("apply host state: %v", err)
	}

	// The client can reach the LAN host it has no route back from.
	if out, err := inNS(t, "cli", "ping", "-c", "1", "-W", "2", "192.168.88.2"); err != nil {
		t.Fatalf("a packet did not cross the gateway: %v\n%s", err, out)
	}
}

// TestWithoutMasqueradeTheReplyNeverReturns is the other half, and it is why
// `orbit route add <gw> 0.0.0.0/0` defaulting masquerade OFF produced an exit
// node that could not work (ADR-0034).
//
// Stated as a test rather than a comment because it is the precondition the
// test above rests on: if the LAN could route back on its own, that test would
// pass with or without NAT and would be asserting nothing.
func TestWithoutMasqueradeTheReplyNeverReturns(t *testing.T) {
	requireNetAdmin(t)
	gatewayWorld(t)

	h := HostState{TunDev: "gw-cli", Forward: true} // forwarding, no NAT
	if err := (&nftConfigurer{network: "test"}).Apply(h); err != nil {
		t.Fatalf("apply host state: %v", err)
	}

	if out, err := inNS(t, "cli", "ping", "-c", "1", "-W", "2", "192.168.88.2"); err == nil {
		t.Errorf("the reply came back without NAT, so the LAN can route to the "+
			"overlay on its own and TestGatewayForwardsAPacket proves nothing:\n%s", out)
	}
}

// TestForwardingIsWithdrawn. A machine that stops being a gateway must stop
// forwarding — leaving the rules is the one uninstall failure with a security
// consequence (ADR-0015).
func TestGatewayForwardingIsWithdrawn(t *testing.T) {
	requireNetAdmin(t)
	gatewayWorld(t)

	cfg := &nftConfigurer{network: "test"}
	h := HostState{
		TunDev: "gw-cli", Forward: true,
		Masquerade: []netip.Prefix{netip.MustParsePrefix("192.168.88.0/24")},
	}
	if err := cfg.Apply(h); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out, err := inNS(t, "cli", "ping", "-c", "1", "-W", "2", "192.168.88.2"); err != nil {
		t.Fatalf("precondition: forwarding did not work at all: %v\n%s", err, out)
	}

	// Withdrawn the way the reconcile loop withdraws it: an empty state.
	if err := cfg.Apply(HostState{}); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if out, err := inNS(t, "cli", "ping", "-c", "1", "-W", "2", "192.168.88.2"); err == nil {
		t.Errorf("the gateway kept forwarding after its state was withdrawn:\n%s", out)
	}
}

// TestTheMSSClampIsAcceptedByARealNftables.
//
// nftscript_test asserts the clamp is in the script Orbit generates. That is a
// different claim from "nft accepts it": `tcp option maxseg size set rt mtu` is
// exactly the kind of expression an older nftables rejects, and a rule the
// kernel refused would take the whole table with it — Apply loads it as ONE
// transaction, so a syntax error means a gateway with no NAT either.
func TestTheMSSClampIsAcceptedByARealNftables(t *testing.T) {
	requireNetAdmin(t)
	gatewayWorld(t)

	h := HostState{
		TunDev: "gw-cli", Forward: true,
		Masquerade: []netip.Prefix{netip.MustParsePrefix("192.168.88.0/24")},
	}
	if err := (&nftConfigurer{network: "test"}).Apply(h); err != nil {
		t.Fatalf("apply: %v", err)
	}

	out, err := exec.Command("nft", "list", "table", "inet", TableName).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "maxseg") {
		t.Errorf("the MSS clamp is not in the live ruleset:\n%s", out)
	}
	if !strings.Contains(string(out), "masquerade") {
		t.Errorf("the NAT rule is not in the live ruleset:\n%s", out)
	}
}
