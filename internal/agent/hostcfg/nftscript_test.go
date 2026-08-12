package hostcfg

import (
	"net/netip"
	"strings"
	"testing"
)

// What a gateway's ruleset must contain, asserted on the ruleset.
//
// The e2e suite covers gateways thoroughly at the level of INTENT — rendered
// YAML and stored state — and no packet crosses a gateway anywhere in it. That
// boundary is where the defects in ADR-0034 live, and it is why none of them
// had been caught: every one of them renders correctly.
//
// A netns forwarding test is still the right end state and is not this. These
// assertions are the cheap half: they catch a rule that is absent or misscoped,
// and they cannot catch a rule that is present and wrong.

func lan() netip.Prefix { return netip.MustParsePrefix("192.168.88.0/24") }

func TestAForwardingGatewayClampsMSS(t *testing.T) {
	got := nftScript(HostState{TunDev: "orbit0", Forward: true})

	if !strings.Contains(got, "hook forward priority mangle") {
		t.Fatalf("no mangle forward chain:\n%s", got)
	}
	if !strings.Contains(got, "tcp option maxseg size set rt mtu") {
		t.Errorf("no MSS clamp. The overlay MTU is 1300 and a LAN is 1500, so a "+
			"full-size segment does not fit the tunnel; without this it depends "+
			"entirely on PMTUD, which Orbit neither installs nor unblocks the ICMP "+
			"for.\n%s", got)
	}
	// SYN only. MSS is carried on SYN and SYN-ACK; matching anything else would
	// be rewriting payload.
	if !strings.Contains(got, "tcp flags syn") {
		t.Errorf("the clamp is not restricted to SYN:\n%s", got)
	}
}

// TestOnlyAForwardingHostClamps. An exit-node CLIENT forwards nothing, so a
// mangle chain there would be rewriting its own traffic for no reason.
func TestOnlyAForwardingHostClamps(t *testing.T) {
	for _, c := range []struct {
		name string
		h    HostState
	}{
		{"masquerade without forwarding", HostState{
			TunDev: "orbit0", Masquerade: []netip.Prefix{lan()}}},
		{"no tun device to scope to", HostState{Forward: true}},
	} {
		if strings.Contains(nftScript(c.h), "maxseg") {
			t.Errorf("%s: clamped anyway", c.name)
		}
	}
}

// TestMasqueradeIsScopedToTheOverlay. Without iifname a gateway would NAT its
// own LAN's traffic to the same destination — somebody else's network changing
// behaviour because Orbit was installed.
func TestMasqueradeIsScopedToTheOverlay(t *testing.T) {
	got := nftScript(HostState{
		TunDev: "orbit0", Forward: true, Masquerade: []netip.Prefix{lan()},
	})
	if !strings.Contains(got, `iifname "orbit0"`) {
		t.Errorf("the masquerade rule is not scoped to the tun:\n%s", got)
	}
	if !strings.Contains(got, "priority srcnat") {
		t.Errorf("NAT is not at srcnat priority:\n%s", got)
	}
}

// TestTheTableIsAlwaysReplacedWholesale. `destroy` then `table` in one
// transaction is what makes Apply idempotent without probing first, and what
// makes a rule somebody edited by hand disappear on the next reconcile.
func TestTheTableIsAlwaysReplacedWholesale(t *testing.T) {
	got := nftScript(HostState{TunDev: "orbit0", Forward: true})
	destroy := strings.Index(got, "destroy table")
	create := strings.Index(got, "table inet "+TableName+" {")
	if destroy < 0 || create < 0 || destroy > create {
		t.Errorf("the script does not destroy-then-create in one transaction:\n%s", got)
	}
}

// TestAnUnreachableExitNodeIsNotEmptyHostState.
//
// HostState.Empty() decides whether the agent applies anything at all. A host
// that chose an exit node the control plane could not render is not a gateway
// and has no masquerade, so without this it looked like a host with nothing to
// do — and the whole point is that it has something to do: fail closed rather
// than fall back to its own physical default. See ADR-0016.
func TestAnUnreachableExitNodeIsNotEmptyHostState(t *testing.T) {
	if (HostState{ExitNodeBlackhole: true}).Empty() {
		t.Error("a host whose exit node vanished read as having no host state, so " +
			"nothing would be applied and its traffic would leave in the clear")
	}
	if !(HostState{}).Empty() {
		t.Error("the zero value stopped being empty; every ordinary host would now apply state")
	}
}

// TestBlackholeAndExitNodeAreDistinctInTheStateString. The agent skips a
// reconcile when the state string is unchanged, so two states that mean
// opposite things must not render the same.
func TestBlackholeAndExitNodeAreDistinctInTheStateString(t *testing.T) {
	up := HostState{ExitNode: true, TunDev: "orbit0"}.String()
	gone := HostState{ExitNodeBlackhole: true, TunDev: "orbit0"}.String()
	if up == gone {
		t.Errorf("a working exit node and a vanished one produce the same state "+
			"string, so the transition between them is a no-op reconcile: %q", up)
	}
}
