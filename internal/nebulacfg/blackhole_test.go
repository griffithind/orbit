package nebulacfg

import (
	"net/netip"
	"strings"
	"testing"
)

// A consumer whose exit node vanished must be TOLD, not silently left on its
// own physical default.
//
// NetworkRoutes filters gateways to enrolled|active, so suspending the gateway
// removes the route from the render entirely — and rendering nothing meant the
// machine that chose an exit node for privacy sent its traffic in the clear,
// with no signal anywhere. Losing internet access is a support call; losing it
// silently to the clear is an incident nobody opens. See ADR-0016.
func TestAnUnreachableExitNodeIsRenderedAsSuch(t *testing.T) {
	base := Input{
		Paths:      PathsFor("net"),
		Firewall:   DefaultFirewall(),
		ListenPort: 4242,
		Lighthouses: []Lighthouse{{
			VpnAddr:     netip.MustParseAddr("10.42.0.1"),
			StaticAddrs: []string{"198.51.100.1:4242"},
		}},
	}

	t.Run("selected and gone", func(t *testing.T) {
		in := base
		in.ExitNodeUnreachable = true
		out, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "exit_node_unreachable: true") {
			t.Errorf("nothing marks the exit node unreachable:\n%s", out)
		}
		// And it must NOT claim to have one, or the agent installs the policy
		// route for a tunnel that is not there.
		if strings.Contains(string(out), "exit_node: true") {
			t.Error("rendered exit_node: true for a route that could not be rendered")
		}
	})

	t.Run("an ordinary host says neither", func(t *testing.T) {
		out, err := Render(base)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "exit_node_unreachable") {
			t.Errorf("a host with no exit node was marked unreachable:\n%s", out)
		}
	})

	t.Run("a working exit node is unchanged", func(t *testing.T) {
		in := base
		in.Routes = []Route{{
			Prefix:   netip.MustParsePrefix("0.0.0.0/0"),
			Gateways: []Gateway{{Addr: netip.MustParseAddr("10.42.0.5")}},
		}}
		out, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "exit_node: true") {
			t.Errorf("a renderable default route did not set exit_node:\n%s", out)
		}
		if strings.Contains(string(out), "exit_node_unreachable") {
			t.Error("a working exit node was marked unreachable")
		}
	})
}
