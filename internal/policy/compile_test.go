package policy

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// testFleet is deliberately awkward: dual stack, one v4-only host, one host
// with no address at all, one gateway routing a subnet, and a host carrying two
// tags. Every one of those is a case the compiler gets wrong by default.
func testFleet() Snapshot {
	return Snapshot{
		CIDRs: []netip.Prefix{
			netip.MustParsePrefix("10.42.0.0/16"),
			netip.MustParsePrefix("fd00:42::/64"),
		},
		Members: []Membership{
			{ID: "h-web1", Name: "web1", Role: "app", Tags: []string{"web", "prod"},
				Addrs: addrs("10.42.0.11", "fd00:42::11")},
			{ID: "h-web2", Name: "web2", Role: "app", Tags: []string{"web"},
				Addrs: addrs("10.42.0.12")},
			{ID: "h-db1", Name: "db1", Role: "db", Tags: []string{"db", "prod"},
				Addrs: addrs("10.42.1.5", "fd00:42::5")},
			{ID: "h-gw", Name: "gw", Role: "gateway", Tags: []string{"gw"},
				Addrs:          addrs("10.42.2.1"),
				UnsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}},
			{ID: "h-new", Name: "new", Tags: []string{"web"}},
		},
	}
}

func mustCompile(t *testing.T, raw []byte, membershipID string, c Compiler) Ruleset {
	t.Helper()
	d, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rs, err := c.Membership(d, membershipID)
	if err != nil {
		t.Fatalf("compile for %s: %v", membershipID, err)
	}
	return rs
}

func cidrs(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.CIDR)
	}
	return out
}

// The central claim: one allowance becomes an inbound rule on the destination
// AND an outbound rule on the source, both keyed on addresses the peer's
// certificate has to authorise.
func TestOneAllowanceCompilesBothDirections(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["tag:web"],"dst":["tag:db"],"proto":"tcp","ports":["5432"]}`)

	db := mustCompile(t, raw, "h-db1", c)
	want := []string{"10.42.0.11/32", "10.42.0.12/32", "fd00:42::11/128"}
	if got := cidrs(db.Inbound); !reflect.DeepEqual(got, want) {
		t.Errorf("db inbound cidrs = %v, want %v", got, want)
	}
	if len(db.Outbound) != 0 {
		t.Errorf("db is not a source in this policy but got outbound rules: %+v", db.Outbound)
	}

	web := mustCompile(t, raw, "h-web1", c)
	if got, want := cidrs(web.Outbound), []string{"10.42.1.5/32", "fd00:42::5/128"}; !reflect.DeepEqual(got, want) {
		t.Errorf("web outbound cidrs = %v, want %v", got, want)
	}
	if len(web.Inbound) != 0 {
		t.Errorf("web is not a destination here but got inbound rules: %+v", web.Inbound)
	}
	for _, r := range append(db.Inbound, web.Outbound...) {
		if r.Proto != "tcp" || r.Port != "5432" {
			t.Errorf("rule lost its port or protocol: %+v", r)
		}
		if r.LocalCIDR != "" {
			t.Errorf("a rule about the host's own address carries a local_cidr: %+v", r)
		}
	}
}

// A tag nobody carries yet is the normal state of a policy written before the
// hosts that will carry it. Refusing it would make "declare the rule, then tag
// hosts into it" impossible, which is the workflow tags exist for.
func TestTagWithNoMembersCompilesToNothing(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["tag:staging"],"dst":["tag:db"],"proto":"tcp","ports":["5432"]}`)

	rs := mustCompile(t, raw, "h-db1", c)
	if len(rs.Inbound) != 0 || len(rs.Outbound) != 0 {
		t.Errorf("an empty tag produced rules: %+v", rs)
	}
	// And it is not an error, in either position.
	raw = doc(`{"src":["tag:db"],"dst":["tag:staging"],"proto":"tcp","ports":["5432"]}`)
	if rs := mustCompile(t, raw, "h-db1", c); len(rs.Outbound) != 0 {
		t.Errorf("an empty destination tag produced outbound rules: %+v", rs.Outbound)
	}
}

// A host that carries two tags named by one entry must not get the same rule
// twice: the rendered config is hashed to decide whether anything changed, and
// duplicate rules are also duplicate work in nebula's table.
func TestHostInTwoTagsIsNotDuplicated(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	// web1 is in both "web" and "prod"; db1 is in both "db" and "prod".
	raw := doc(`{"src":["tag:web","tag:prod"],"dst":["tag:db","tag:prod"],"proto":"tcp","ports":["443"]}`)

	rs := mustCompile(t, raw, "h-db1", c)
	seen := map[Rule]int{}
	for _, r := range rs.Inbound {
		seen[r]++
	}
	for r, n := range seen {
		if n > 1 {
			t.Errorf("rule emitted %d times: %+v", n, r)
		}
	}
	// db1 is itself in "prod", so it is a source too and gets outbound rules —
	// but never one naming its own address.
	for _, r := range append(rs.Inbound, rs.Outbound...) {
		if r.CIDR == "10.42.1.5/32" || r.CIDR == "fd00:42::5/128" {
			t.Errorf("a host got a rule naming its own address: %+v", r)
		}
	}
}

// host: and id: name one specific entity, so naming nothing is a dangling
// reference — a typo, or something deleted out from under the policy. That has
// to fail loudly, because in authoritative mode the alternative is a host that
// silently talks to nobody.
func TestPolicyNamingAMissingHostIsRefused(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	for _, sel := range []string{"host:ghost", "id:h-nope"} {
		d, err := Parse(doc(`{"src":["` + sel + `"],"dst":["tag:db"],"proto":"tcp","ports":["5432"]}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Membership(d, "h-db1")
		if err == nil {
			t.Fatalf("%s compiled against a fleet that has no such host", sel)
		}
		if !strings.Contains(err.Error(), "names no host") || !strings.Contains(err.Error(), "allow[0] src") {
			t.Errorf("the error does not locate the dangling reference: %v", err)
		}
	}
}

// A role that matches nothing is NOT an error, and the asymmetry with host: is
// deliberate: the fleet view is hosts, so an unused role and a misspelt role
// are indistinguishable here, and refusing would break declaring a role's
// policy before any host holds it.
func TestUnusedRoleIsNotAnError(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["role:batch"],"dst":["tag:db"],"proto":"tcp","ports":["5432"]}`)
	if rs := mustCompile(t, raw, "h-db1", c); len(rs.Inbound) != 0 {
		t.Errorf("an unheld role produced rules: %+v", rs.Inbound)
	}
}

// firewallPort.addRule builds one map entry per port in a range, so 1-65535
// builds 65535 structs per rule. "any" is one entry and means the same thing.
func TestFullPortRangeCompilesToAny(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["tag:web"],"dst":["tag:db"],"proto":"tcp","ports":["1-65535"]}`)
	rs := mustCompile(t, raw, "h-db1", c)
	if len(rs.Inbound) == 0 {
		t.Fatal("no rules")
	}
	for _, r := range rs.Inbound {
		if r.Port != "any" {
			t.Errorf("full range rendered as %q, which builds 65535 firewall entries", r.Port)
		}
	}
}

// The agent hashes the rendered config to decide whether anything changed. Map
// iteration order must never reach the output.
func TestCompilationIsDeterministic(t *testing.T) {
	c := Compiler{
		Fleet: testFleet(),
		Management: []Endpoint{
			{Addr: netip.MustParseAddr("10.42.0.2"), Port: 8446},
		},
	}
	raw := doc(`
		{"src":["*"],"dst":["tag:db"],"proto":"tcp","ports":["5432","443","80"]},
		{"src":["tag:web","tag:prod"],"dst":["tag:prod"],"proto":"any","ports":["any"]},
		{"src":["cidr:10.42.0.0/24"],"dst":["host:db1"],"proto":"icmp"}`)

	d, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.Membership(d, "h-db1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		got, err := c.Membership(d, "h-db1")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("compilation %d differs from the first:\n%+v\n%+v", i, got, first)
		}
	}

	// And All must agree with Membership, or a preview would not describe what is
	// actually rendered.
	all, err := c.All(d)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(all["h-db1"], first) {
		t.Errorf("All and Membership disagree:\n%+v\n%+v", all["h-db1"], first)
	}
}

// A v4-only host in a dual-stack network must get v4 rules and no malformed v6
// ones — and its peers must not get a rule for a v6 address it does not hold.
func TestV4OnlyHostInADualStackNetwork(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["tag:web"],"dst":["tag:db"],"proto":"tcp","ports":["5432"]}`)

	web2 := mustCompile(t, raw, "h-web2", c)
	// It still reaches both of the destination's addresses: which family the
	// packet uses is the sender's routing decision, not the policy's.
	if got, want := cidrs(web2.Outbound), []string{"10.42.1.5/32", "fd00:42::5/128"}; !reflect.DeepEqual(got, want) {
		t.Errorf("v4-only host outbound = %v, want %v", got, want)
	}
	// And the destination admits exactly one prefix for it, in the right family.
	db := mustCompile(t, raw, "h-db1", c)
	n := 0
	for _, r := range db.Inbound {
		if strings.HasPrefix(r.CIDR, "10.42.0.12") {
			n++
			if r.CIDR != "10.42.0.12/32" {
				t.Errorf("v4 host rendered as %q", r.CIDR)
			}
		}
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			t.Fatalf("emitted an unparseable cidr %q", r.CIDR)
		}
		if p.Bits() != p.Addr().BitLen() {
			t.Errorf("a host address rendered as %q rather than a single-address prefix", r.CIDR)
		}
	}
	if n != 1 {
		t.Errorf("the v4-only host contributed %d rules, want 1", n)
	}
}

// "*" is where compiling to addresses pays off: Orbit owns address assignment,
// so "every host in this network" is the network's prefixes — one rule per
// prefix rather than one per host. It is NOT `host: any`, which would also
// admit a peer holding a valid certificate from a trusted CA that Orbit never
// placed in this network.
func TestWildcardCompilesToTheNetworkPrefixes(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["*"],"dst":["host:db1"],"proto":"tcp","ports":["5432"]}`)
	rs := mustCompile(t, raw, "h-db1", c)

	want := []string{"10.42.0.0/16", "fd00:42::/64"}
	if got := cidrs(rs.Inbound); !reflect.DeepEqual(got, want) {
		t.Errorf("wildcard inbound = %v, want %v", got, want)
	}
	for _, r := range rs.Inbound {
		if r.CIDR == "any" {
			t.Error("the compiler emitted a matches-everything cidr")
		}
	}
}

// A dst inside a subnet a host ROUTES is the trap that validates, renders,
// deploys and quietly does nothing: with local_cidr empty and unsafe networks
// present, nebula narrows the rule to the host's own addresses
// (firewallLocalCIDR.addRule), and Orbit never sets default_local_cidr_any.
func TestRoutedSubnetGetsAnExplicitLocalCIDR(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["tag:web"],"dst":["cidr:192.168.50.0/24"],"proto":"tcp","ports":["443"]}`)

	gw := mustCompile(t, raw, "h-gw", c)
	if len(gw.Inbound) == 0 {
		t.Fatal("the gateway got no inbound rule for the subnet it routes")
	}
	for _, r := range gw.Inbound {
		if r.LocalCIDR != "192.168.50.0/24" {
			t.Errorf("rule for a routed subnet has local_cidr %q; nebula would narrow it to "+
				"the gateway's own addresses and the rule would do nothing: %+v", r.LocalCIDR, r)
		}
	}

	// The sender's half is symmetric: it reaches the subnet, not the gateway's
	// own address.
	web := mustCompile(t, raw, "h-web1", c)
	if got, want := cidrs(web.Outbound), []string{"192.168.50.0/24"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sender outbound = %v, want %v", got, want)
	}
}

// And in the other direction: traffic FROM behind the gateway needs the
// gateway's outbound rule scoped to what it is forwarding.
func TestRoutedSubnetAsSourceScopesTheSendersRule(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["cidr:192.168.50.0/24"],"dst":["tag:db"],"proto":"tcp","ports":["5432"]}`)

	gw := mustCompile(t, raw, "h-gw", c)
	if len(gw.Outbound) == 0 {
		t.Fatal("the gateway got no outbound rule for the subnet it forwards")
	}
	for _, r := range gw.Outbound {
		if r.LocalCIDR != "192.168.50.0/24" {
			t.Errorf("forwarded traffic's outbound rule has local_cidr %q: %+v", r.LocalCIDR, r)
		}
	}
	db := mustCompile(t, raw, "h-db1", c)
	if got, want := cidrs(db.Inbound), []string{"192.168.50.0/24"}; !reflect.DeepEqual(got, want) {
		t.Errorf("receiver inbound = %v, want %v", got, want)
	}
}

func TestCIDROutsideTheNetworkIsRefused(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	d, err := Parse(doc(`{"src":["cidr:8.8.8.0/24"],"dst":["tag:db"],"proto":"tcp","ports":["5432"]}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Membership(d, "h-db1")
	if err == nil {
		t.Fatal("a prefix no certificate in this network could authorise was accepted")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("the refusal does not explain why: %v", err)
	}
	// An unoccupied prefix INSIDE the network is fine: reserving a range for
	// hosts that do not exist yet is a legitimate way to write a policy.
	d, err = Parse(doc(`{"src":["cidr:10.42.200.0/24"],"dst":["tag:db"],"proto":"tcp","ports":["5432"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Membership(d, "h-db1"); err != nil {
		t.Errorf("an unoccupied in-network prefix was refused: %v", err)
	}
}

// A host with no address yet compiles to nothing rather than to a rule naming
// an address somebody else will be given.
func TestUnassignedHostContributesNoPeerRule(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["tag:web"],"dst":["tag:db"],"proto":"tcp","ports":["5432"]}`)
	rs := mustCompile(t, raw, "h-db1", c)
	if len(rs.Inbound) != 3 {
		t.Errorf("want 3 inbound rules (web1 v4+v6, web2 v4), got %d: %+v", len(rs.Inbound), rs.Inbound)
	}
}

// Dropping the outbound allow-all in authoritative mode means a policy that
// forgets the control plane takes the fleet offline AND removes the API you
// would use to fix it. The floor is the compiler's answer, and it is not
// negotiable.
func TestManagementFloor(t *testing.T) {
	c := Compiler{
		Fleet: Snapshot{
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
			Members: []Membership{
				{ID: "h-cp", Name: "control-plane", Addrs: addrs("10.42.0.2")},
				{ID: "h-a", Name: "a", Addrs: addrs("10.42.0.10")},
			},
		},
		Management: []Endpoint{{Addr: netip.MustParseAddr("10.42.0.2"), Port: 8446}},
	}
	// A document that says nothing at all.
	d, err := Parse([]byte(`{"version":1,"allow":[]}`))
	if err != nil {
		t.Fatal(err)
	}

	agent, err := c.Membership(d, "h-a")
	if err != nil {
		t.Fatal(err)
	}
	want := Rule{Proto: "tcp", Port: "8446", CIDR: "10.42.0.2/32"}
	if len(agent.Outbound) != 1 || agent.Outbound[0] != want {
		t.Errorf("an agent cannot reach the control plane under an empty policy: %+v", agent.Outbound)
	}
	if len(agent.Inbound) != 0 {
		t.Errorf("the floor opened the agent to inbound traffic: %+v", agent.Inbound)
	}

	cp, err := c.Membership(d, "h-cp")
	if err != nil {
		t.Fatal(err)
	}
	wantIn := Rule{Proto: "tcp", Port: "8446", CIDR: "10.42.0.0/16"}
	if len(cp.Inbound) != 1 || cp.Inbound[0] != wantIn {
		t.Errorf("the control plane does not accept the agent API: %+v", cp.Inbound)
	}
	// It does not need an outbound rule to itself.
	if len(cp.Outbound) != 0 {
		t.Errorf("the control plane got an outbound rule to itself: %+v", cp.Outbound)
	}
}

func TestCompilingForAHostOutsideTheFleet(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	d, _ := Parse([]byte(`{"version":1,"allow":[]}`))
	if _, err := c.Membership(d, "h-elsewhere"); err == nil {
		t.Fatal("compiled rules for a host that is not in this network")
	}
}

// Nothing the compiler emits can match everything by accident. A group named
// "any", a host named "any", or a cidr of "any" all short-circuit
// FirewallRule.isAny, and the compiler must be structurally incapable of
// producing one.
func TestNothingMatchesEverythingByAccident(t *testing.T) {
	c := Compiler{Fleet: testFleet(), Management: []Endpoint{
		{Addr: netip.MustParseAddr("10.42.0.2"), Port: 8446},
	}}
	raw := doc(`
		{"src":["*"],"dst":["*"],"proto":"any","ports":["any"]},
		{"src":["tag:web"],"dst":["cidr:192.168.50.0/24"],"proto":"tcp","ports":["443"]}`)
	d, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	all, err := c.All(d)
	if err != nil {
		t.Fatal(err)
	}
	for id, rs := range all {
		for _, r := range append(rs.Inbound, rs.Outbound...) {
			if r.CIDR == "any" || r.CIDR == "" {
				t.Errorf("%s: rule with no address constraint: %+v", id, r)
			}
			if _, err := netip.ParsePrefix(r.CIDR); err != nil {
				t.Errorf("%s: unparseable cidr in %+v", id, r)
			}
			if r.LocalCIDR != "" {
				if _, err := netip.ParsePrefix(r.LocalCIDR); err != nil {
					t.Errorf("%s: unparseable local_cidr in %+v", id, r)
				}
			}
		}
	}
}

func TestPortOrderingIsNumericForReviewers(t *testing.T) {
	c := Compiler{Fleet: testFleet()}
	raw := doc(`{"src":["tag:web"],"dst":["host:db1"],"proto":"tcp","ports":["8080","80","443","any"]}`)
	rs := mustCompile(t, raw, "h-db1", c)

	var ports []string
	for _, r := range rs.Inbound {
		if r.CIDR == "10.42.0.12/32" {
			ports = append(ports, r.Port)
		}
	}
	if want := []string{"any", "80", "443", "8080"}; !reflect.DeepEqual(ports, want) {
		t.Errorf("ports ordered %v, want %v", ports, want)
	}
}
