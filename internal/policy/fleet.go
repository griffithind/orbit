package policy

import "net/netip"

// Fleet is the view of a network the compiler resolves selectors against.
//
// Narrow on purpose, and an interface rather than a store handle, so that
// compilation is a pure function of (document, fleet) with no database, no
// context and no clock in it. Everything interesting about this package is
// testable from a literal.
type Fleet interface {
	// Memberships returns every host a selector may name, in any order. The compiler
	// sorts what it needs to; a caller must not have to.
	Memberships() []Membership

	// Prefixes returns the network's overlay CIDRs. They bound which cidr:
	// selectors are meaningful, and they are what "*" compiles to: since Orbit
	// owns address assignment, "every address in this network" is one rule per
	// prefix rather than one rule per host.
	Prefixes() []netip.Prefix
}

// Membership is one member of a network, as far as policy is concerned.
type Membership struct {
	// ID is the Orbit host id, matched by id: and used to address a compiled
	// ruleset. A string rather than a uuid.UUID because nothing here needs to
	// parse it, and a plain string keeps this package free of dependencies.
	ID string

	// Name is the name in the host's certificate, matched by host:.
	Name string

	// Role is the host's role name, matched by role:. Empty when it has none.
	Role string

	// Tags are matched by tag:. Until this package existed, tags were inert —
	// stored and read back, never reaching a certificate or a rule.
	Tags []string

	// Addrs are the host's assigned overlay addresses. A host with none cannot
	// be a rule's peer and is skipped: an unassigned host compiles to nothing
	// rather than to a rule matching an address somebody else will be given.
	Addrs []netip.Addr

	// UnsafeNetworks are subnets this host routes into the overlay.
	//
	// Orbit does not issue certificates carrying these yet, so this is empty in
	// practice, and it is modelled anyway because of a trap that only bites
	// once it is not. When a rule's local_cidr is empty and the host HAS unsafe
	// networks and firewall.default_local_cidr_any is unset — Orbit never sets
	// it — the rule applies ONLY to the host's own addresses and not to the
	// subnets it routes (firewall.go, firewallLocalCIDR.addRule). A dst naming
	// a routed subnet then validates, renders, deploys, and quietly does
	// nothing. The compiler emits an explicit local_cidr for exactly that case.
	UnsafeNetworks []netip.Prefix
}

// Snapshot is a Fleet held in memory: what a store query produces, and what a
// test writes by hand.
type Snapshot struct {
	Members []Membership
	CIDRs   []netip.Prefix
}

func (s Snapshot) Memberships() []Membership { return s.Members }
func (s Snapshot) Prefixes() []netip.Prefix  { return s.CIDRs }

// hasAddr reports whether the host holds a.
func (h Membership) hasAddr(a netip.Addr) bool {
	for _, x := range h.Addrs {
		if x == a {
			return true
		}
	}
	return false
}

// membershipPrefix is a host address as the single-address prefix a nebula cidr: rule
// takes. /32 for v4 and /128 for v6, so a v4-only host in a dual-stack network
// contributes v4 rules and nothing else rather than a mangled v6 one.
func membershipPrefix(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}
