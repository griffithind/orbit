package hostcfg

import (
	"bytes"
	"fmt"
)

// The gateway ruleset, as data.
//
// Shared rather than linux-tagged even though only Linux applies it, because
// every property worth asserting about it — that a forwarding host clamps MSS,
// that a NAT rule is scoped to the tun, that a non-gateway renders nothing — is
// a property of this string, and a test that can only run on one platform is a
// test that does not run on the machine most of this is written on.

const nftFamily = "inet"

// nftScript renders the whole table as one transaction.
//
// Pure, and separated from Apply for that reason: every property worth asserting
// about a gateway's ruleset — that a forwarding host clamps MSS, that a NAT rule
// is scoped to the tun, that a non-gateway renders nothing — is a property of
// this string, and testing it through Apply would need root, nft, and a machine
// willing to have its firewall rewritten.
func nftScript(h HostState) string {
	// One transaction. `destroy` rather than `delete` so a first run, where the
	// table does not exist, is not an error — and so the whole thing is
	// idempotent without a probe first.
	var b bytes.Buffer
	fmt.Fprintf(&b, "destroy table %s %s\n", nftFamily, TableName)
	fmt.Fprintf(&b, "table %s %s {\n", nftFamily, TableName)

	if h.Forward && h.TunDev != "" {
		// MSS CLAMPING, and it is the difference between a subnet route that
		// works and one that works for small packets.
		//
		// The overlay MTU is 1300 (nebulacfg.defaultTunMTU) and the LAN behind a
		// gateway is 1500, so a full-size segment from the LAN side does not fit
		// in the tunnel. The kernel is supposed to answer with ICMP Frag Needed
		// and the sender is supposed to shrink — but PMTUD is broken often
		// enough on the public internet that "supposed to" is not a design, and
		// Orbit neither installs nor unblocks that ICMP. Nebula does not help
		// either: it sets AdvMSS only when a route's MTU differs from the
		// device's, which with Orbit's defaults it never does.
		//
		// `rt mtu` clamps to the outgoing route's MTU, so this is correct in
		// BOTH directions without knowing which is which — and both directions
		// is the point. Clamping only one black-holes large segments the other
		// way when PMTUD fails, which is the mistake Tailscale's ClampMSSToPMTU
		// comment calls out.
		//
		// Matching SYN alone is deliberate: MSS is only carried on SYN and
		// SYN-ACK, and rewriting anything else would be rewriting payload.
		// See docs/adr/0034-the-gateway-data-path-is-tested.md.
		fmt.Fprintf(&b, "  chain mangle_forward {\n")
		fmt.Fprintf(&b, "    type filter hook forward priority mangle; policy accept;\n")
		fmt.Fprintf(&b, "    tcp flags syn / syn,rst tcp option maxseg size set rt mtu counter\n")
		fmt.Fprintf(&b, "  }\n")
	}

	if len(h.Masquerade) > 0 {
		// priority srcnat (100) is where NAT belongs in the postrouting hook;
		// anything else either runs before the routing decision is final or
		// after something else has already rewritten the packet.
		fmt.Fprintf(&b, "  chain postrouting {\n")
		fmt.Fprintf(&b, "    type nat hook postrouting priority srcnat; policy accept;\n")
		for _, p := range h.Masquerade {
			fam := "ip"
			if p.Addr().Is6() {
				fam = "ip6"
			}
			// Scoped to traffic that ARRIVED on the overlay. Without iifname a
			// gateway would masquerade its own LAN's traffic to the same
			// destination, which is somebody else's network silently changing
			// behaviour because Orbit was installed.
			fmt.Fprintf(&b, "    iifname %q %s daddr %s counter masquerade comment \"orbit route %s\"\n",
				h.TunDev, fam, p.String(), p.String())
		}
		fmt.Fprintf(&b, "  }\n")
	}
	fmt.Fprintf(&b, "}\n")

	return b.String()
}
