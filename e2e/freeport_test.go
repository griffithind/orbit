package e2e

import (
	"fmt"
	"net"
	"testing"
)

// The property the old helper did not have.
//
// Asking the kernel for :0 closes the probe socket before returning, so two
// calls could legitimately be handed the same port — and a single test boots
// several nebulas off several calls. This is the regression guard: it fails
// against the previous implementation.
func TestFreeUDPPortNeverRepeats(t *testing.T) {
	seen := map[int]bool{}
	for i := range 300 {
		p := freeUDPPort(t)
		if seen[p] {
			t.Fatalf("port %d handed out twice, on call %d", p, i)
		}
		seen[p] = true
		if p < portLo || p >= portHi {
			t.Fatalf("port %d is outside the private range %d-%d, so the kernel "+
				"may hand it to an unrelated connection", p, portLo, portHi)
		}
	}
}

// A port handed out must actually be bindable the way nebula binds it — the
// dual-stack wildcard, not 127.0.0.1. A probe on the loopback address cannot
// see a conflict on any other address.
func TestFreeUDPPortIsBindableAsNebulaBindsIt(t *testing.T) {
	p := freeUDPPort(t)
	c, err := net.ListenPacket("udp", fmt.Sprintf(":%d", p))
	if err != nil {
		t.Fatalf("a port reported free could not be bound on the wildcard: %v", err)
	}
	defer c.Close()
}
