package nebulacfg

import (
	"net/netip"
	"testing"
)

// A gateway's inbound rules must cover what it forwards, and nothing enforced
// that. See docs/adr/0021-gateway-reachability-is-derived-from-routes.md.
//
// The failure this pins is delayed past its cause: `orbit route add` puts the
// prefix into the gateway's next certificate, and it is the ARRIVAL of that
// certificate — minutes to hours later — that narrows every rule with an
// omitted local_cidr down to the host's own addresses. Forwarding works, then
// stops, and nothing connects the two events.
func TestAServedPrefixWidensRulesWithNoLocalCIDR(t *testing.T) {
	lan := netip.MustParsePrefix("192.168.88.0/24")

	in := Input{
		Paths:      PathsFor("net"),
		ListenPort: 4242,
		Lighthouses: []Lighthouse{{
			VpnAddr:     netip.MustParseAddr("10.42.0.1"),
			StaticAddrs: []string{"198.51.100.1:4242"},
		}},
		Firewall: &Firewall{
			Outbound: []Rule{{Port: "any", Proto: "any", Host: "any"}},
			Inbound: []Rule{
				// The ordinary case: no local_cidr, because the author meant
				// "wherever this host answers".
				{Port: "22", Proto: "tcp", Groups: []string{"admin"}},
				// And one that says where it applies, which must be left alone.
				{Port: "443", Proto: "tcp", Host: "any", LocalCIDR: "10.42.0.0/16"},
			},
		},
		Serves: []Served{{Prefix: lan, Masquerade: true}},
	}

	out, err := Render(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	fw := parsedFirewall(t, string(out))

	var widened, original, untouched int
	for _, r := range fw.Inbound {
		switch {
		case r.Port == "22" && r.LocalCIDR == lan.String():
			widened++
		case r.Port == "22" && r.LocalCIDR == "":
			original++
		case r.Port == "443" && r.LocalCIDR == "10.42.0.0/16":
			untouched++
		default:
			t.Errorf("unexpected rule after widening: %+v", r)
		}
	}

	if widened != 1 {
		t.Errorf("the served prefix produced %d explicit local_cidr rules, want 1.\n"+
			"Without one, nebula narrows the rule to this host's own addresses and "+
			"drops everything it forwards.", widened)
	}
	if original != 1 {
		t.Errorf("the original rule was %d times present, want 1: nebula still narrows "+
			"it to the host's own addresses, which is wanted", original)
	}
	if untouched != 1 {
		t.Errorf("a rule that named its own local_cidr was rewritten; the author said " +
			"where it applies and that is not ours to widen")
	}
}

// TestAHostThatServesNothingIsUnchanged. The overwhelming majority of hosts
// route nothing, and on those an omitted local_cidr already means "any" —
// widening them would add rules for no reason and change bytes every reviewer
// has learned to read.
func TestAHostThatServesNothingIsUnchanged(t *testing.T) {
	base := Input{
		Paths:      PathsFor("net"),
		ListenPort: 4242,
		Lighthouses: []Lighthouse{{
			VpnAddr:     netip.MustParseAddr("10.42.0.1"),
			StaticAddrs: []string{"198.51.100.1:4242"},
		}},
		Firewall: &Firewall{
			Outbound: []Rule{{Port: "any", Proto: "any", Host: "any"}},
			Inbound:  []Rule{{Port: "22", Proto: "tcp", Groups: []string{"admin"}}},
		},
	}

	out, err := Render(base)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if fw := parsedFirewall(t, string(out)); len(fw.Inbound) != 1 {
		t.Errorf("a host serving nothing rendered %d inbound rules, want 1", len(fw.Inbound))
	}
}
