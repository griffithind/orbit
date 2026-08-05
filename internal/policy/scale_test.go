// This file is package policy_test rather than package policy because it
// measures the RENDERED artifact, and rendering lives in nebulacfg, which
// imports policy. The number that matters to an operator is bytes on the wire
// per poll, not rules in a struct.
package policy_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/policy"
)

// scaleFleet builds n hosts, each with one v4 address, tagged into `tiers`
// groups plus a tag every host carries.
func scaleFleet(n, tiers int) policy.Snapshot {
	s := policy.Snapshot{CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	s.Members = make([]policy.Membership, 0, n)
	for i := 0; i < n; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		s.Members = append(s.Members, policy.Membership{
			ID:    fmt.Sprintf("h-%05d", i),
			Name:  fmt.Sprintf("host-%05d", i),
			Role:  fmt.Sprintf("tier-%d", i%tiers),
			Tags:  []string{"fleet", fmt.Sprintf("tier-%d", i%tiers)},
			Addrs: []netip.Addr{a},
		})
	}
	return s
}

// allToAll is the worst realistic shape: every host may reach every other on a
// handful of ports, expressed by tag rather than by wildcard. It is the shape
// that produces one rule per peer per entry, which is the O(peers × entries)
// growth this measurement exists to bound.
func allToAll(entries int) policy.Document {
	d := policy.Document{Version: policy.Version}
	for i := 0; i < entries; i++ {
		d.Allow = append(d.Allow, policy.Entry{
			Src:   []policy.Selector{"tag:fleet"},
			Dst:   []policy.Selector{"tag:fleet"},
			Proto: "tcp",
			Ports: []string{fmt.Sprintf("%d", 9000+i)},
		})
	}
	return d
}

// tiered is what a real policy looks like: traffic flows between named tiers,
// not from everything to everything.
func tiered(tiers int) policy.Document {
	d := policy.Document{Version: policy.Version}
	for i := 0; i < tiers; i++ {
		d.Allow = append(d.Allow, policy.Entry{
			Src:   []policy.Selector{policy.Selector(fmt.Sprintf("tag:tier-%d", i))},
			Dst:   []policy.Selector{policy.Selector(fmt.Sprintf("tag:tier-%d", (i+1)%tiers))},
			Proto: "tcp",
			Ports: []string{"443"},
		})
	}
	// One wildcard entry, which is the cheap case: "*" is the network's
	// prefixes, so it costs one rule however large the fleet is.
	d.Allow = append(d.Allow, policy.Entry{
		Src: []policy.Selector{"*"}, Dst: []policy.Selector{"tag:tier-0"},
		Proto: "tcp", Ports: []string{"22"},
	})
	return d
}

func renderWith(t *testing.T, rs policy.Ruleset) int {
	t.Helper()
	out, err := nebulacfg.Render(nebulacfg.Input{
		Paths:      nebulacfg.PathsFor("scale"),
		Policy:     &rs,
		ListenPort: 4242,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return len(out)
}

// TestRenderedSizeAtScale is the cost measurement, not a pass/fail assertion.
//
// Each host's configuration grows O(peers × entries), and renderFor regenerates
// it per host per epoch, so a fleet-wide push is O(N² × entries) BYTES. The
// numbers below are the ones to design against; go test -v prints the table.
func TestRenderedSizeAtScale(t *testing.T) {
	t.Log("all-to-all (tag:fleet -> tag:fleet), the worst realistic shape")
	t.Logf("%6s %8s %8s %10s %12s", "hosts", "entries", "rules", "per-host", "fleet push")
	for _, n := range []int{10, 50, 100, 250, 500, 1000, 2000} {
		fleet := scaleFleet(n, 4)
		c := policy.Compiler{Fleet: fleet}
		doc := allToAll(3)

		rs, err := c.Membership(doc, fleet.Members[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		size := renderWith(t, rs)
		t.Logf("%6d %8d %8d %10s %12s",
			n, len(doc.Allow), len(rs.Inbound)+len(rs.Outbound),
			bytes(size), bytes(size*n))
	}

	t.Log("")
	t.Log("tiered (tier -> tier, plus one wildcard entry), a realistic shape")
	t.Logf("%6s %8s %8s %10s %12s", "hosts", "entries", "rules", "per-host", "fleet push")
	for _, n := range []int{100, 1000, 5000} {
		fleet := scaleFleet(n, 8)
		c := policy.Compiler{Fleet: fleet}
		doc := tiered(8)

		rs, err := c.Membership(doc, fleet.Members[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		size := renderWith(t, rs)
		t.Logf("%6d %8d %8d %10s %12s",
			n, len(doc.Allow), len(rs.Inbound)+len(rs.Outbound),
			bytes(size), bytes(size*n))
	}
}

func bytes(n int) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// The rendered document must be byte-identical across renders, because the
// agent hashes it to decide whether to apply anything. A single unstable byte
// at fleet scale turns every poll into a full re-apply.
func TestRenderedPolicyIsByteIdentical(t *testing.T) {
	fleet := scaleFleet(200, 5)
	c := policy.Compiler{
		Fleet:      fleet,
		Management: []policy.Endpoint{{Addr: netip.MustParseAddr("10.0.0.0"), Port: 8446}},
	}
	doc := allToAll(3)
	doc.Allow = append(doc.Allow, tiered(5).Allow...)

	rs, err := c.Membership(doc, fleet.Members[7].ID)
	if err != nil {
		t.Fatal(err)
	}
	first, err := nebulacfg.Render(nebulacfg.Input{Paths: nebulacfg.PathsFor("scale"),
		Policy: &rs, ListenPort: 4242,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := c.Membership(doc, fleet.Members[7].ID)
		if err != nil {
			t.Fatal(err)
		}
		out, err := nebulacfg.Render(nebulacfg.Input{Paths: nebulacfg.PathsFor("scale"),
			Policy: &again, ListenPort: 4242,
		})
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != string(first) {
			t.Fatalf("render %d differs from the first", i)
		}
	}
}

// BenchmarkCompileHost is the per-poll cost. Every agent poll that finds a new
// epoch pays it once, and the fleet pays it N times per epoch.
func BenchmarkCompileHost(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		fleet := scaleFleet(n, 8)
		c := policy.Compiler{Fleet: fleet}
		doc := allToAll(5)
		id := fleet.Members[0].ID
		b.Run(fmt.Sprintf("hosts=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := c.Membership(doc, id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkCompileAll is the same work done once for the whole network.
//
// The gap between this and N × CompileHost is the size of the prize from
// resolving the document once, and it is SMALL: resolution is linear in the
// fleet while emission is quadratic, so emission dominates almost immediately.
// The cache worth building is of rendered per-host configs keyed by epoch, not
// of resolved selectors.
func BenchmarkCompileAll(b *testing.B) {
	for _, n := range []int{100, 500} {
		fleet := scaleFleet(n, 8)
		c := policy.Compiler{Fleet: fleet}
		doc := allToAll(5)
		b.Run(fmt.Sprintf("hosts=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := c.All(doc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
