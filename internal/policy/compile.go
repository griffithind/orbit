package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Rule is one compiled nebula firewall rule.
//
// Deliberately only the four fields the compiler can emit. There is no Host,
// no Groups and no CAName, because compiling to addresses is the whole design
// (see the package comment) and a field that is always empty is a field a
// reader has to check. There is no Code either: nebula's own error says support
// for it will be dropped because it has never been functional.
type Rule struct {
	Proto string
	Port  string
	CIDR  string

	// LocalCIDR is empty for the ordinary case, which nebula reads as "this
	// host's own addresses" when it routes unsafe networks and as "anywhere"
	// when it does not. It is set only when the allowance named a subnet this
	// host routes, which is the case that silently does nothing without it.
	LocalCIDR string
}

// Ruleset is one host's compiled firewall. Both slices are sorted and free of
// duplicates, so the same inputs render the same bytes.
type Ruleset struct {
	Inbound  []Rule
	Outbound []Rule
}

// Endpoint is a control plane replica's agent API on the overlay.
type Endpoint struct {
	Addr netip.Addr
	Port int
}

// Compiler turns a Document into per-host rules.
type Compiler struct {
	Fleet Fleet

	// Management is the control plane's agent API, and the rules derived from
	// it are the ONE thing the compiler emits that the document did not ask
	// for.
	//
	// In authoritative mode a policy is the complete firewall, so publishing
	// one that forgets the control plane does not merely break the agent API —
	// it removes the path every host uses to fetch the fix, including the fix
	// that would restore it. That is a lockout with no recovery short of
	// touching every machine. The floor is two rules wide (outbound to the
	// replicas on every host, inbound from the network on the replicas
	// themselves) and it is not negotiable.
	//
	// Empty disables it, which is correct only when the caller knows the agent
	// API is not reached over this network.
	Management []Endpoint
}

// Host compiles one host's rules.
func (c Compiler) Host(doc Document, hostID string) (Ruleset, error) {
	hosts := c.Fleet.Hosts()
	idx := slices.IndexFunc(hosts, func(h Host) bool { return h.ID == hostID })
	if idx < 0 {
		return Ruleset{}, fmt.Errorf("%w: host %s is not in this network", ErrInvalid, hostID)
	}
	entries, err := c.resolveAll(doc)
	if err != nil {
		return Ruleset{}, err
	}
	return c.emit(entries, hosts[idx]), nil
}

// All compiles every host's rules, keyed by host id.
//
// The bulk form exists because resolving the document is the expensive half and
// it is identical for every host: rendering a whole network through Host would
// redo it N times. Callers that render one host per agent poll pay that cost by
// construction; see the measurements in scale_test.go.
func (c Compiler) All(doc Document) (map[string]Ruleset, error) {
	entries, err := c.resolveAll(doc)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Ruleset, len(c.Fleet.Hosts()))
	for _, h := range c.Fleet.Hosts() {
		out[h.ID] = c.emit(entries, h)
	}
	return out, nil
}

// side is one end of an allowance, resolved against the fleet.
type side struct {
	// own holds the hosts this side names by their own overlay addresses. A
	// rule for them carries no local_cidr, which nebula reads as the host's own
	// addresses once it routes anything.
	own map[string]bool

	// routed holds, per host, the subnets this side named that the host routes
	// rather than owns. Each becomes an explicit local_cidr.
	routed map[string][]netip.Prefix

	// peers are the prefixes to emit as cidr: on the far end's rules.
	peers []netip.Prefix
}

type resolvedEntry struct {
	src, dst side
	proto    string
	ports    []string
}

func (s side) names(h Host) bool { return s.own[h.ID] || len(s.routed[h.ID]) > 0 }

// localCIDRs is the set of local_cidr values this side implies for h. Empty
// string means "leave the key off", which is a distinct and useful value.
func (s side) localCIDRs(h Host) []string {
	var out []string
	if s.own[h.ID] {
		out = append(out, "")
	}
	for _, p := range s.routed[h.ID] {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (c Compiler) resolveAll(doc Document) ([]resolvedEntry, error) {
	out := make([]resolvedEntry, 0, len(doc.Allow))
	for i, e := range doc.Allow {
		src, err := c.resolve(e.Src)
		if err != nil {
			return nil, fmt.Errorf("allow[%d] src: %w", i, err)
		}
		dst, err := c.resolve(e.Dst)
		if err != nil {
			return nil, fmt.Errorf("allow[%d] dst: %w", i, err)
		}
		ports, err := compilePorts(e)
		if err != nil {
			return nil, fmt.Errorf("allow[%d]: %w", i, err)
		}
		out = append(out, resolvedEntry{src: src, dst: dst, proto: e.Proto, ports: ports})
	}
	return out, nil
}

func (c Compiler) resolve(sels []Selector) (side, error) {
	s := side{own: map[string]bool{}, routed: map[string][]netip.Prefix{}}
	hosts := c.Fleet.Hosts()

	for _, raw := range sels {
		sel, err := parseSelector(raw)
		if err != nil {
			// Parse validates every selector, so reaching here means the
			// Document was built in Go rather than parsed. Still an error, not
			// a panic.
			return side{}, fmt.Errorf("%q: %w", raw, err)
		}

		switch sel.kind {
		case selAll:
			// "*" is where compiling to addresses pays off twice. Orbit owns
			// address assignment, so "every host in this network" IS the
			// network's prefixes: one rule per prefix instead of one per host,
			// and it stays correct as hosts are added and removed without a
			// re-render.
			//
			// Not `host: any`, which would also match a peer holding a valid
			// certificate from a trusted CA that Orbit did not place in this
			// network.
			s.peers = append(s.peers, c.Fleet.Prefixes()...)
			for _, h := range hosts {
				if len(h.Addrs) > 0 {
					s.own[h.ID] = true
				}
			}

		case selHost, selID, selTag, selRole:
			matched := 0
			for _, h := range hosts {
				if !selectorMatches(sel, h) {
					continue
				}
				matched++
				if len(h.Addrs) == 0 {
					// An unassigned host compiles to nothing rather than to a
					// rule naming an address somebody else will be given.
					continue
				}
				s.own[h.ID] = true
				for _, a := range h.Addrs {
					s.peers = append(s.peers, hostPrefix(a))
				}
			}
			// host: and id: name ONE specific entity, so naming nothing is a
			// dangling reference: a typo, or something deleted out from under
			// the policy. tag: and role: name a set, and an empty set is the
			// normal state of a policy written before the hosts that will carry
			// it — refusing that would make "declare the rule, then tag hosts
			// into it" impossible, which is the workflow tags are for.
			if matched == 0 && (sel.kind == selHost || sel.kind == selID) {
				return side{}, fmt.Errorf("%w: %s names no host in this network", ErrInvalid, raw)
			}

		case selCIDR:
			if !c.withinFleet(sel.prefix) {
				return side{}, fmt.Errorf("%w: cidr %s is outside this network's address space "+
					"and outside every routed subnet in it, so no certificate could ever "+
					"authorise an address in it", ErrInvalid, sel.prefix)
			}
			s.peers = append(s.peers, sel.prefix)
			for _, h := range hosts {
				for _, a := range h.Addrs {
					if sel.prefix.Contains(a) {
						s.own[h.ID] = true
						break
					}
				}
				for _, u := range h.UnsafeNetworks {
					// Contained in a subnet this host routes: the rule is about
					// traffic passing THROUGH the host, so it needs an explicit
					// local_cidr or nebula narrows it to the host's own
					// addresses and the rule quietly does nothing.
					if u.Bits() <= sel.prefix.Bits() && u.Contains(sel.prefix.Addr()) {
						s.routed[h.ID] = append(s.routed[h.ID], sel.prefix)
					}
				}
			}
		}
	}
	return s, nil
}

func selectorMatches(sel selector, h Host) bool {
	switch sel.kind {
	case selHost:
		return h.Name == sel.value
	case selID:
		return h.ID == sel.value
	case selRole:
		return h.Role != "" && h.Role == sel.value
	case selTag:
		return slices.Contains(h.Tags, sel.value)
	}
	return false
}

// withinFleet reports whether p is an address range this network could ever
// authorise: inside one of its overlay prefixes, or inside a subnet one of its
// hosts routes.
func (c Compiler) withinFleet(p netip.Prefix) bool {
	for _, n := range c.Fleet.Prefixes() {
		if n.Bits() <= p.Bits() && n.Contains(p.Addr()) {
			return true
		}
	}
	for _, h := range c.Fleet.Hosts() {
		for _, u := range h.UnsafeNetworks {
			if u.Bits() <= p.Bits() && u.Contains(p.Addr()) {
				return true
			}
		}
	}
	return false
}

// compilePorts turns an entry's ports into the strings nebula's parsePort takes.
func compilePorts(e Entry) ([]string, error) {
	if e.Proto == "icmp" {
		return []string{"any"}, nil
	}
	out := make([]string, 0, len(e.Ports))
	for _, p := range e.Ports {
		p = strings.TrimSpace(p)
		if p == "any" {
			out = append(out, "any")
			continue
		}
		lo, hi, isRange := strings.Cut(p, "-")
		l, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("%w: port %q", ErrInvalid, p)
		}
		if !isRange {
			out = append(out, strconv.Itoa(l))
			continue
		}
		h, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil {
			return nil, fmt.Errorf("%w: port %q", ErrInvalid, p)
		}
		if isFullPortRange(l, h) {
			// The trap this exists for: firewallPort.addRule materialises one
			// map entry per port, so "1-65535" builds 65535 structs per rule.
			// "any" is one, and means the same thing.
			out = append(out, "any")
			continue
		}
		out = append(out, strconv.Itoa(l)+"-"+strconv.Itoa(h))
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// emit produces one host's rules from the resolved document.
func (c Compiler) emit(entries []resolvedEntry, self Host) Ruleset {
	in := map[Rule]struct{}{}
	out := map[Rule]struct{}{}

	for _, e := range entries {
		// Inbound: this host is a destination, so admit the sources.
		if e.dst.names(self) {
			emitRules(in, self, e.src.peers, e.dst.localCIDRs(self), e.proto, e.ports)
		}
		// Outbound: this host is a source, so permit reaching the destinations.
		// Enforced on the sender against the DESTINATION's certificate, which
		// is why the same peer prefixes work in both directions.
		if e.src.names(self) {
			emitRules(out, self, e.dst.peers, e.src.localCIDRs(self), e.proto, e.ports)
		}
	}

	c.managementFloor(self, in, out)

	return Ruleset{Inbound: sortRules(in), Outbound: sortRules(out)}
}

func emitRules(dst map[Rule]struct{}, self Host, peers []netip.Prefix, localCIDRs []string, proto string, ports []string) {
	for _, p := range peers {
		// A host is never its own peer over the tunnel: a packet to itself does
		// not traverse nebula, so a rule naming its own address is dead weight
		// and reads as a puzzle. Only exact single-address prefixes are
		// dropped; a wider prefix that happens to contain this host still
		// applies to everybody else in it.
		if p.Bits() == p.Addr().BitLen() && self.hasAddr(p.Addr()) {
			continue
		}
		for _, lc := range localCIDRs {
			for _, port := range ports {
				dst[Rule{Proto: proto, Port: port, CIDR: p.String(), LocalCIDR: lc}] = struct{}{}
			}
		}
	}
}

func (c Compiler) managementFloor(self Host, in, out map[Rule]struct{}) {
	for _, ep := range c.Management {
		if !ep.Addr.IsValid() || ep.Port <= 0 {
			continue
		}
		port := strconv.Itoa(ep.Port)
		if self.hasAddr(ep.Addr) {
			// This host IS a control plane replica. Every managed host has to
			// reach it, and which hosts those are is the whole network.
			for _, n := range c.Fleet.Prefixes() {
				in[Rule{Proto: "tcp", Port: port, CIDR: n.String()}] = struct{}{}
			}
			continue
		}
		out[Rule{Proto: "tcp", Port: port, CIDR: hostPrefix(ep.Addr).String()}] = struct{}{}
	}
}

// sortRules gives the map a total order so the render is byte-identical run to
// run. Keys are precomputed rather than parsed inside the comparator: at fleet
// scale the comparator runs O(n log n) times and prefix parsing is not free.
func sortRules(set map[Rule]struct{}) []Rule {
	type keyed struct {
		rule   Rule
		portLo int
		addr   netip.Addr
		bits   int
	}
	ks := make([]keyed, 0, len(set))
	for r := range set {
		k := keyed{rule: r, portLo: portOrder(r.Port)}
		if p, err := netip.ParsePrefix(r.CIDR); err == nil {
			k.addr, k.bits = p.Addr(), p.Bits()
		}
		ks = append(ks, k)
	}
	slices.SortFunc(ks, func(a, b keyed) int {
		if v := strings.Compare(a.rule.Proto, b.rule.Proto); v != 0 {
			return v
		}
		if v := a.portLo - b.portLo; v != 0 {
			return v
		}
		if v := strings.Compare(a.rule.Port, b.rule.Port); v != 0 {
			return v
		}
		if v := a.addr.Compare(b.addr); v != 0 {
			return v
		}
		if v := a.bits - b.bits; v != 0 {
			return v
		}
		return strings.Compare(a.rule.LocalCIDR, b.rule.LocalCIDR)
	})
	rules := make([]Rule, 0, len(ks))
	for _, k := range ks {
		rules = append(rules, k.rule)
	}
	return rules
}

// portOrder sorts "any" first and numeric ports numerically, so a reviewer
// reads 80 before 443 before 8080 rather than 443, 80, 8080.
func portOrder(p string) int {
	if p == "any" {
		return -1
	}
	lo, _, _ := strings.Cut(p, "-")
	n, err := strconv.Atoi(lo)
	if err != nil {
		return 1 << 20
	}
	return n
}
