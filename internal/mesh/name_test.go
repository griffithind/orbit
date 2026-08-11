package mesh

import (
	"net/netip"
	"os"
	"testing"
)

// TestTwoReplicasOnOneAddressGetDifferentNames.
//
// The whole defence against two control planes sharing an overlay address is
// SelfIssue's "reuse only if the name matches". That check was inert: the name
// was derived from the address it was refereeing, so two replicas given the
// same -mesh address computed the same name, the refusal never fired, and the
// second adopted the first's membership. Both self-issued certificates for one
// overlay IP.
//
// This asserts the property the check depends on — the name distinguishes
// machines, not addresses — rather than the string itself.
func TestTwoReplicasOnOneAddressGetDifferentNames(t *testing.T) {
	addr := netip.MustParseAddr("10.42.0.1")

	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skip("no hostname on this machine; the fallback path is the old behaviour by design")
	}

	name := defaultName(addr)
	if name == "orbit-control-"+addr.String() {
		t.Fatal("the name is still derived from the address, so SelfIssue's refusal " +
			"cannot fire for two replicas sharing one -mesh address")
	}
	if name != "orbit-control-"+host {
		t.Errorf("name = %q, want it to name the machine", name)
	}

	// Stable across calls: a replica restarting has to reclaim its own record,
	// which it can only do if the name it computes has not moved.
	if again := defaultName(addr); again != name {
		t.Errorf("name is not stable: %q then %q; a restart would be refused", name, again)
	}

	// And it does not depend on the address, which is what makes two replicas
	// on one address distinguishable.
	if other := defaultName(netip.MustParseAddr("10.42.0.2")); other != name {
		t.Errorf("name changed with the address (%q vs %q); it must identify the machine", name, other)
	}
}
