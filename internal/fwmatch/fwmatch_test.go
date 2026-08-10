package fwmatch

import (
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/firewall"
)

// The grammar under test, from nebula's firewall.go:
//
//	port AND proto AND (ca_sha OR ca_name) AND (host OR group OR groups OR cidr) AND (local_cidr)
//
// Every case below pins one term of it. The package had no unit tests at all,
// which is why two divergences from nebula shipped: a ca_sha rule that failed
// OPEN, and a proto-any question that missed every rule.

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// baseQuery is a query that matches a wide-open rule, so a table case only has
// to state the term it is exercising.
func baseQuery() Query {
	return Query{
		PeerAddr:      addr("10.0.0.2"),
		LocalAddr:     addr("10.0.0.1"),
		Proto:         firewall.ProtoTCP,
		Port:          443,
		PeerCertKnown: true,
		PeerName:      "web-01",
		PeerGroups:    []string{"web", "default"},
		PeerCAName:    "corp",
		PeerCASha:     "aabb",
	}
}

func anyRule() Rule {
	return Rule{StartPort: firewall.PortAny, EndPort: firewall.PortAny, Proto: firewall.ProtoAny}
}

type judgeCase struct {
	name string
	rule func(Rule) Rule
	qry  func(Query) Query
	want Outcome
}

func run(t *testing.T, cases []judgeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, q := anyRule(), baseQuery()
			if tc.rule != nil {
				r = tc.rule(r)
			}
			if tc.qry != nil {
				q = tc.qry(q)
			}
			got, why := judge(r, q)
			if got != tc.want {
				t.Errorf("judge = %v (%s), want %v", got, why, tc.want)
			}
		})
	}
}

// TestCATermIsADisjunction. nebula's grammar is (ca_sha OR ca_name); a rule
// applies if EITHER names the peer's issuer.
func TestCATermIsADisjunction(t *testing.T) {
	run(t, []judgeCase{
		{
			name: "sha only, matching",
			rule: func(r Rule) Rule { r.CASha = "aabb"; return r },
			want: Matches,
		},
		{
			// The regression. A sha-only rule whose sha does NOT match, against a
			// query carrying no CA name, used to fall through to Matches because
			// the guard's final conjunct compared "" != "".
			name: "sha only, wrong sha, empty peer CA name",
			rule: func(r Rule) Rule { r.CASha = "ccdd"; return r },
			qry:  func(q Query) Query { q.PeerCAName = ""; return q },
			want: Misses,
		},
		{
			name: "sha only, wrong sha, peer CA name set and different",
			rule: func(r Rule) Rule { r.CASha = "ccdd"; return r },
			want: Misses,
		},
		{
			name: "name only, matching",
			rule: func(r Rule) Rule { r.CAName = "corp"; return r },
			want: Matches,
		},
		{
			name: "name only, not matching",
			rule: func(r Rule) Rule { r.CAName = "other"; return r },
			want: Misses,
		},
		{
			name: "both set, sha matches and name does not",
			rule: func(r Rule) Rule { r.CASha, r.CAName = "aabb", "other"; return r },
			want: Matches,
		},
		{
			name: "both set, name matches and sha does not",
			rule: func(r Rule) Rule { r.CASha, r.CAName = "ccdd", "corp"; return r },
			want: Matches,
		},
		{
			name: "both set, neither matches",
			rule: func(r Rule) Rule { r.CASha, r.CAName = "ccdd", "other"; return r },
			want: Misses,
		},
		{
			name: "no certificate at all",
			rule: func(r Rule) Rule { r.CAName = "corp"; return r },
			qry:  func(q Query) Query { q.PeerCertKnown = false; return q },
			want: Unknown,
		},
		{
			// The asymmetry that made the fail-open reachable: the agent's peer
			// table carries name and groups but no issuer, so it sets
			// PeerCertKnown with both CA fields empty. That is Unknown, not a
			// verdict either way.
			name: "certificate known but issuer not",
			rule: func(r Rule) Rule { r.CASha = "aabb"; return r },
			qry: func(q Query) Query {
				q.PeerCAName, q.PeerCASha = "", ""
				return q
			},
			want: Unknown,
		},
		{
			name: "rule names no CA, so the issuer is irrelevant",
			qry: func(q Query) Query {
				q.PeerCAName, q.PeerCASha = "", ""
				return q
			},
			want: Matches,
		},
	})
}

// TestProtoTerm. A rule's "any" permits every protocol; a query's "any" asks the
// weaker question "is anything permitted at all", which every rule answers.
func TestProtoTerm(t *testing.T) {
	run(t, []judgeCase{
		{
			name: "rule any matches a tcp question",
			want: Matches,
		},
		{
			// The regression: `orbit why` defaults -proto to any.
			name: "tcp rule answers an any question",
			rule: func(r Rule) Rule { r.Proto = firewall.ProtoTCP; return r },
			qry:  func(q Query) Query { q.Proto = firewall.ProtoAny; return q },
			want: Matches,
		},
		{
			name: "udp rule answers an any question",
			rule: func(r Rule) Rule { r.Proto = firewall.ProtoUDP; return r },
			qry:  func(q Query) Query { q.Proto = firewall.ProtoAny; return q },
			want: Matches,
		},
		{
			name: "tcp rule does not answer a udp question",
			rule: func(r Rule) Rule { r.Proto = firewall.ProtoTCP; return r },
			qry:  func(q Query) Query { q.Proto = firewall.ProtoUDP; return q },
			want: Misses,
		},
		{
			// ICMP and ICMPv6 share a table in nebula and a name in the config.
			name: "icmp rule matches an icmpv6 question",
			rule: func(r Rule) Rule { r.Proto = firewall.ProtoICMP; return r },
			qry:  func(q Query) Query { q.Proto = firewall.ProtoICMPv6; return q },
			want: Matches,
		},
		{
			name: "icmpv6 rule matches an icmp question",
			rule: func(r Rule) Rule { r.Proto = firewall.ProtoICMPv6; return r },
			qry:  func(q Query) Query { q.Proto = firewall.ProtoICMP; return q },
			want: Matches,
		},
	})
}

// TestPortTerm mirrors TestProtoTerm: the two terms must treat "any" the same
// way in both directions, and they did not.
func TestPortTerm(t *testing.T) {
	ports := func(lo, hi int32) func(Rule) Rule {
		return func(r Rule) Rule { r.StartPort, r.EndPort = lo, hi; return r }
	}
	at := func(p int32) func(Query) Query {
		return func(q Query) Query { q.Port = p; return q }
	}
	run(t, []judgeCase{
		{name: "rule any permits any port", qry: at(9999), want: Matches},
		{name: "any question answered by a narrow rule", rule: ports(80, 80), qry: at(firewall.PortAny), want: Matches},
		{name: "inside the range", rule: ports(80, 443), qry: at(200), want: Matches},
		{name: "low boundary", rule: ports(80, 443), qry: at(80), want: Matches},
		{name: "high boundary", rule: ports(80, 443), qry: at(443), want: Matches},
		{name: "just below", rule: ports(80, 443), qry: at(79), want: Misses},
		{name: "just above", rule: ports(80, 443), qry: at(444), want: Misses},
	})
}

// TestSelectorTerm. (host OR group OR groups OR cidr), with groups AND-ing
// within one rule — the peer must carry every group listed.
func TestSelectorTerm(t *testing.T) {
	run(t, []judgeCase{
		{
			name: "host exact",
			rule: func(r Rule) Rule { r.Host = "web-01"; return r },
			want: Matches,
		},
		{
			name: "host mismatch",
			rule: func(r Rule) Rule { r.Host = "db-01"; return r },
			want: Misses,
		},
		{
			name: "groups all present",
			rule: func(r Rule) Rule { r.Groups = []string{"web", "default"}; return r },
			want: Matches,
		},
		{
			name: "groups subset present is not enough",
			rule: func(r Rule) Rule { r.Groups = []string{"web", "admin"}; return r },
			want: Misses,
		},
		{
			name: "peer carrying extra groups still matches",
			rule: func(r Rule) Rule { r.Groups = []string{"web"}; return r },
			want: Matches,
		},
		{
			name: "cidr containing the peer",
			rule: func(r Rule) Rule { r.CIDR = "10.0.0.0/24"; return r },
			want: Matches,
		},
		{
			name: "cidr not containing the peer",
			rule: func(r Rule) Rule { r.CIDR = "10.1.0.0/24"; return r },
			want: Misses,
		},
		{
			// The decidability property the whole Unknown outcome rests on: a
			// cidr rule is answerable from the address alone, so no certificate
			// is needed.
			name: "cidr rule is decidable without a certificate",
			rule: func(r Rule) Rule { r.CIDR = "10.0.0.0/24"; return r },
			qry:  func(q Query) Query { q.PeerCertKnown = false; return q },
			want: Matches,
		},
		{
			name: "group rule is not decidable without a certificate",
			rule: func(r Rule) Rule { r.Groups = []string{"web"}; return r },
			qry:  func(q Query) Query { q.PeerCertKnown = false; return q },
			want: Unknown,
		},
	})
}

// TestLocalCIDRTerm filters the destination, which is how a routed subnet is
// exposed selectively.
func TestLocalCIDRTerm(t *testing.T) {
	run(t, []judgeCase{
		{name: "empty is any", rule: func(r Rule) Rule { r.LocalCIDR = ""; return r }, want: Matches},
		{name: "explicit any", rule: func(r Rule) Rule { r.LocalCIDR = "any"; return r }, want: Matches},
		{
			name: "containing the local address",
			rule: func(r Rule) Rule { r.LocalCIDR = "10.0.0.0/24"; return r },
			want: Matches,
		},
		{
			name: "not containing the local address",
			rule: func(r Rule) Rule { r.LocalCIDR = "10.9.0.0/24"; return r },
			want: Misses,
		},
		{
			name: "unparseable prefix misses rather than panics",
			rule: func(r Rule) Rule { r.LocalCIDR = "not-a-prefix"; return r },
			want: Misses,
		},
	})
}

// TestDecideCombinesRules. Cross-rule OR, and the rule that an undecidable rule
// must not mask a decisive one.
func TestDecideCombinesRules(t *testing.T) {
	q := baseQuery()

	t.Run("one match beats one unknown", func(t *testing.T) {
		open := anyRule()
		unknowable := anyRule()
		unknowable.Groups = []string{"web"}
		u := q
		u.PeerCertKnown = false

		d := Decide([]Rule{unknowable, open}, u)
		if !d.Allowed {
			t.Error("a decisive match must win over an undecidable rule")
		}
		if d.Undecidable {
			t.Error("Undecidable must be false when something matched")
		}
	})

	t.Run("only unknown is undecidable, not denied", func(t *testing.T) {
		unknowable := anyRule()
		unknowable.Groups = []string{"web"}
		u := q
		u.PeerCertKnown = false

		d := Decide([]Rule{unknowable}, u)
		if d.Allowed {
			t.Error("an undecidable rule must not allow")
		}
		if !d.Undecidable {
			t.Error("an undecidable rule must say so rather than reporting a denial")
		}
	})

	t.Run("empty ruleset denies", func(t *testing.T) {
		d := Decide(nil, q)
		if d.Allowed || d.Undecidable {
			t.Errorf("empty ruleset: Allowed=%v Undecidable=%v, want false/false", d.Allowed, d.Undecidable)
		}
		if d.Considered != 0 {
			t.Errorf("Considered = %d, want 0", d.Considered)
		}
	})

	t.Run("considered counts every rule", func(t *testing.T) {
		miss := anyRule()
		miss.Host = "nope"
		d := Decide([]Rule{miss, miss, miss}, q)
		if d.Considered != 3 {
			t.Errorf("Considered = %d, want 3", d.Considered)
		}
	})
}
