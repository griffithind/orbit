// Package fwmatch answers "would nebula's firewall let this through".
//
// # Why nebula parses the rules and Orbit only matches them
//
// The obvious implementation reads the firewall section out of a configuration
// and interprets it. That is two re-implementations, not one: the parser AND
// the matcher, and the parser is the larger and fiddlier of the two — port
// ranges, `port: fragment`, the group/groups flattening, ICMP's coerced ports,
// the proto names, the local_cidr default that depends on whether the host
// routes unsafe networks.
//
// nebula exports both halves of what is needed to avoid that.
// AddFirewallRulesFromConfig reads the config and calls AddRule on any
// FirewallInterface, so handing it a collector makes NEBULA the parser and
// leaves Orbit only the matching. Every quirk above is then upstream's problem
// and stays correct when upstream changes it.
//
// # What is still a second implementation, and how it is held honest
//
// The matching is ours. FirewallTable.match is unexported and Firewall.Drop
// needs a *HostInfo whose fields are unexported, so there is no way to delegate
// the verdict itself. Second implementations drift, and a diagnostic that
// confidently reports the wrong answer is worse than none.
//
// The mitigation is a cross-check rather than a promise: e2e/why_test.go boots
// two real nebula instances on userspace devices, opens real TCP connections
// across a matrix of ports, and asserts this package agreed with what actually
// happened. A divergence is a test failure, not a support ticket.
//
// # Why it is its own package
//
// Two callers, and they must not be able to disagree. `orbit why` on a host
// asks about the configuration nebula is running; `orbit why <src> <dst>`
// against the control plane asks about rulesets the compiler produced for two
// hosts. If those answers came from different code, an operator could be told
// one thing by the server and the opposite by the machine — which is worse than
// either command not existing.
package fwmatch

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// nebula's firewall constants, redeclared so this package imports nothing.
//
// internal/wire embeds a Decision, and every API client embeds wire — so two
// struct fields were enough to link nebula, gvisor and wireguard into
// internal/adminclient, a package that makes HTTP requests and nothing else.
//
// These are IANA protocol numbers plus two sentinels, and they are part of the
// configuration grammar an operator writes rather than an internal detail. They
// are still a duplicate, so internal/fwmatch/parse asserts at compile time that
// the two sets agree: if nebula renumbers one, that package stops building
// rather than this one silently disagreeing with the firewall it models.
const (
	ProtoAny    uint8 = 0
	ProtoICMP   uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58

	PortAny      int32 = 0
	PortFragment int32 = -1
)

// Rule is one firewall rule, exactly as nebula parsed it.
type Rule struct {
	Incoming  bool     `json:"incoming"`
	Proto     uint8    `json:"proto"`
	StartPort int32    `json:"start_port"`
	EndPort   int32    `json:"end_port"`
	Groups    []string `json:"groups,omitempty"`
	Host      string   `json:"membership,omitempty"`
	CIDR      string   `json:"cidr,omitempty"`
	LocalCIDR string   `json:"local_cidr,omitempty"`
	CAName    string   `json:"ca_name,omitempty"`
	CASha     string   `json:"ca_sha,omitempty"`
}

// String renders a rule the way an operator would have written it.
func (r Rule) String() string {
	parts := []string{"proto " + ProtoName(r.Proto), "port " + PortRange(r.StartPort, r.EndPort)}
	if len(r.Groups) > 0 {
		parts = append(parts, "groups ["+strings.Join(r.Groups, " ")+"]")
	}
	if r.Host != "" {
		parts = append(parts, "host "+r.Host)
	}
	if r.CIDR != "" {
		parts = append(parts, "cidr "+r.CIDR)
	}
	if r.LocalCIDR != "" {
		parts = append(parts, "local_cidr "+r.LocalCIDR)
	}
	if r.CAName != "" {
		parts = append(parts, "ca_name "+r.CAName)
	}
	if r.CASha != "" {
		parts = append(parts, "ca_sha "+r.CASha)
	}
	return strings.Join(parts, ", ")
}

// ProtoName is nebula's protocol constant as an operator writes it.
func ProtoName(p uint8) string {
	switch p {
	case ProtoAny:
		return "any"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP, ProtoICMPv6:
		return "icmp"
	}
	return fmt.Sprint(p)
}

// PortRange renders a rule's port span.
func PortRange(start, end int32) string {
	switch {
	case start == PortAny:
		return "any"
	case start == PortFragment:
		return "fragment"
	case start == end:
		return fmt.Sprint(start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

// Query is one question: may this traffic pass?
type Query struct {
	// PeerAddr is the other end. For an outbound question it is the
	// destination; for inbound, the source. Either way it is what nebula's
	// rules match with host:, cidr: and groups:.
	PeerAddr netip.Addr

	// LocalAddr is this end's own overlay address, which local_cidr matches.
	LocalAddr netip.Addr

	// Proto is a Proto* constant, and Port the DESTINATION port in
	// both directions (nebula firewall/packet.go). PortAny asks the
	// weaker question "is any traffic at all permitted".
	Proto uint8
	Port  int32

	// PeerCertKnown is false when the asker has no verified certificate for the
	// peer, which is the case on a host with no tunnel to it. Rules selecting
	// by group, host or CA are then unevaluable, and saying so is the whole
	// point of carrying this flag.
	PeerCertKnown bool
	PeerName      string
	PeerGroups    []string

	// PeerCAName and PeerCASha identify the CA that issued the peer's
	// certificate, and are SEPARATE from PeerCertKnown on purpose.
	//
	// A caller can hold a verified certificate and still not know its issuer —
	// the agent's peer table carries name and groups but not the issuer, so it
	// sets PeerCertKnown and leaves both of these empty. Folding the two into
	// one flag is what made a ca_sha rule report Matches for a peer issued by a
	// different CA: the guard read "known certificate" as "known issuer" and
	// compared against an empty string. See judge.
	PeerCAName string
	PeerCASha  string
}

// caKnown reports whether this query can answer a question about the issuing CA.
func (q Query) caKnown() bool {
	return q.PeerCertKnown && (q.PeerCAName != "" || q.PeerCASha != "")
}

// Outcome is a rule's relationship to a query.
type Outcome string

const (
	// Matches: this rule permits the traffic.
	Matches Outcome = "matches"
	// Unknown: this rule might permit it, but deciding needs the peer's
	// certificate and the asker does not have one.
	Unknown Outcome = "unknown"
	// Misses: this rule does not permit it. Reason says which term failed.
	Misses Outcome = "misses"
)

// RuleOutcome is one rule judged against one query.
type RuleOutcome struct {
	Rule    Rule    `json:"rule"`
	Outcome Outcome `json:"outcome"`
	Reason  string  `json:"reason,omitempty"`
}

// Decision is the answer for one direction.
type Decision struct {
	// Allowed is true only when a rule definitely matches. A query that could
	// not be decided is Allowed false with Undecidable true — never a quiet
	// "denied", which would be a confident wrong answer in the direction that
	// sends an operator looking in the wrong place.
	Allowed     bool `json:"allowed"`
	Undecidable bool `json:"undecidable,omitempty"`

	// Matched are the rules that permit it. Near are rules that reach this peer
	// but fail on protocol or port — the near misses, which are what an
	// operator wants when the answer is no.
	Matched []RuleOutcome `json:"matched,omitempty"`
	Near    []RuleOutcome `json:"near,omitempty"`

	// Considered is how many rules were in this direction's table at all.
	Considered int `json:"considered"`
}

// Decide judges a query against one direction's rules.
func Decide(rules []Rule, q Query) Decision {
	d := Decision{Considered: len(rules)}
	for _, r := range rules {
		oc, reason := judge(r, q)
		switch oc {
		case Matches:
			d.Matched = append(d.Matched, RuleOutcome{Rule: r, Outcome: oc})
		case Unknown:
			d.Undecidable = true
			d.Near = append(d.Near, RuleOutcome{Rule: r, Outcome: oc, Reason: reason})
		default:
			// Only rules that could reach this peer are worth showing. A rule
			// naming a different host is noise; one naming THIS host on the
			// wrong port is the answer.
			if reachesPeer(r, q) {
				d.Near = append(d.Near, RuleOutcome{Rule: r, Outcome: oc, Reason: reason})
			}
		}
	}
	d.Allowed = len(d.Matched) > 0
	if d.Allowed {
		// A definite match settles it; an unevaluable rule elsewhere in the
		// table cannot make an allowed flow less allowed.
		d.Undecidable = false
	}
	return d
}

// judge is the match, mirroring the grammar at nebula firewall.go:88:
//
//	proto AND port AND (ca_sha OR ca_name) AND local_cidr AND (group OR host OR cidr)
func judge(r Rule, q Query) (Outcome, string) {
	if !protoMatches(r.Proto, q.Proto) {
		return Misses, "protocol"
	}
	if !portMatches(r, q.Port) {
		return Misses, "port"
	}
	// The CA term is a DISJUNCTION of positive matches: nebula's grammar is
	// (ca_sha OR ca_name), so the rule applies if either names the peer's
	// issuer, and misses if neither does.
	//
	// Written as positive matches rather than as negative guards, because the
	// negative form fails OPEN. The previous
	//
	//	if r.CASha != "" && r.CASha != q.PeerCASha && r.CAName != q.PeerCAName
	//
	// collapsed for a ca_sha-only rule against a query with an empty
	// PeerCAName: the third conjunct is "" != "", which is false, so the guard
	// never fired and a rule pinned to a CA the peer was NOT issued by was
	// reported as permitting the traffic.
	if r.CAName != "" || r.CASha != "" {
		if !q.caKnown() {
			return Unknown, "needs the peer's issuing CA to check this rule"
		}
		shaOK := r.CASha != "" && r.CASha == q.PeerCASha
		nameOK := r.CAName != "" && r.CAName == q.PeerCAName
		if !shaOK && !nameOK {
			return Misses, "issuing CA"
		}
	}
	if !localCIDRMatches(r.LocalCIDR, q.LocalAddr) {
		return Misses, "local_cidr"
	}
	return selectorMatches(r, q)
}

func protoMatches(rule, want uint8) bool {
	if rule == ProtoAny {
		return true
	}
	// "Any protocol" as a QUESTION is weaker than a rule's "any", exactly as it
	// is for ports below: it asks whether anything at all is permitted, so every
	// rule answers it.
	//
	// Its absence here was not cosmetic. `orbit why` defaults -proto to "any",
	// which is ProtoAny, so the DEFAULT invocation of the diagnostic
	// reported "no rule permits this traffic" against every tcp-only policy and
	// listed the rules that did permit it as near-misses on "protocol".
	if want == ProtoAny {
		return true
	}
	// ICMP and ICMPv6 share a table in nebula and a name in the config.
	if isICMP(rule) && isICMP(want) {
		return true
	}
	return rule == want
}

func isICMP(p uint8) bool { return p == ProtoICMP || p == ProtoICMPv6 }

func portMatches(r Rule, want int32) bool {
	if r.StartPort == PortAny {
		return true
	}
	// "Any port" as a QUESTION is weaker than a rule's "any": it asks whether
	// anything at all is permitted, so every rule answers it.
	if want == PortAny {
		return true
	}
	return want >= r.StartPort && want <= r.EndPort
}

// localCIDRMatches handles the empty case the way nebula does when the host
// routes no unsafe networks, which is every host Orbit issues for today:
// firewallLocalCIDR.addRule treats "" as "any" unless unsafe networks exist.
func localCIDRMatches(localCIDR string, local netip.Addr) bool {
	if localCIDR == "" || localCIDR == "any" {
		return true
	}
	p, err := netip.ParsePrefix(localCIDR)
	if err != nil {
		return false
	}
	return local.IsValid() && p.Contains(local)
}

// selectorMatches is the (group OR host OR cidr) term.
func selectorMatches(r Rule, q Query) (Outcome, string) {
	if isAnySelector(r) {
		return Matches, ""
	}

	// cidr first: it needs nothing but the address, so a rule that matches on
	// it is decidable even with no tunnel. This is also why Orbit compiles
	// policy to cidr — see docs/policy-model.md.
	if r.CIDR != "" {
		if p, err := netip.ParsePrefix(r.CIDR); err == nil && p.Contains(q.PeerAddr) {
			return Matches, ""
		}
	}

	needsCert := r.Host != "" || len(r.Groups) > 0
	if needsCert && !q.PeerCertKnown {
		return Unknown, "needs the peer's certificate to check its name or groups"
	}
	if r.Host != "" && r.Host == q.PeerName {
		return Matches, ""
	}
	if len(r.Groups) > 0 && hasAllGroups(q.PeerGroups, r.Groups) {
		return Matches, ""
	}
	return Misses, "selector"
}

func isAnySelector(r Rule) bool {
	if len(r.Groups) == 0 && r.Host == "" && r.CIDR == "" {
		return true
	}
	return slices.Contains(r.Groups, "any") || r.Host == "any" || r.CIDR == "any"
}

// hasAllGroups is AND within one rule's group list, matching nebula
// firewall.go:859. Separate rules OR together, which Decide's loop does.
func hasAllGroups(have, want []string) bool {
	for _, g := range want {
		if !slices.Contains(have, g) {
			return false
		}
	}
	return len(want) > 0
}

// reachesPeer reports whether a rule's selector could ever name this peer,
// which decides whether a miss is worth showing to an operator.
func reachesPeer(r Rule, q Query) bool {
	oc, _ := selectorMatches(r, q)
	return oc != Misses
}

// ParseProto turns a protocol name into nebula's constant.
func ParseProto(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "", "any":
		return ProtoAny, nil
	case "tcp":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	case "icmp":
		return ProtoICMP, nil
	}
	return 0, fmt.Errorf("unknown protocol %q: nebula supports any, tcp, udp and icmp", s)
}

// ParsePort turns a port in a QUESTION into nebula's constant. Unlike a rule's
// port this is never a range: a packet has one destination port.
func ParsePort(s string) (int32, error) {
	switch strings.ToLower(s) {
	case "", "any":
		return PortAny, nil
	case "fragment":
		return PortFragment, nil
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("port %q is not in [0,65535]", s)
	}
	return int32(n), nil
}
