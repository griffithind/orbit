package nebulacfg

import (
	"net/netip"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/griffithind/orbit/internal/policy"
)

func testRuleset() policy.Ruleset {
	return policy.Ruleset{
		Inbound: []policy.Rule{
			{Proto: "tcp", Port: "5432", CIDR: "10.42.0.11/32"},
			{Proto: "tcp", Port: "443", CIDR: "192.168.50.0/24", LocalCIDR: "192.168.50.0/24"},
		},
		Outbound: []policy.Rule{
			{Proto: "tcp", Port: "8446", CIDR: "10.42.0.2/32"},
		},
	}
}

func renderPolicy(t *testing.T) string {
	t.Helper()
	rs := testRuleset()
	out, err := Render(Input{
		Paths:      PathsFor("net"),
		Policy:     &rs,
		ListenPort: 4242,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return string(out)
}

func parsedFirewall(t *testing.T, body string) Firewall {
	t.Helper()
	var doc struct {
		Firewall Firewall `yaml:"firewall"`
	}
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("the rendered config is not valid yaml: %v", err)
	}
	return doc.Firewall
}

// Authoritative mode owns the whole file, so the compiled outbound half is
// rendered and the allow-all is gone. That is what makes the two-ended
// enforcement real rather than decorative.
func TestAuthoritativeRendersBothHalves(t *testing.T) {
	fw := parsedFirewall(t, renderPolicy(t))

	if len(fw.Inbound) != 2 {
		t.Fatalf("inbound = %+v", fw.Inbound)
	}
	if len(fw.Outbound) != 1 {
		t.Fatalf("outbound = %+v", fw.Outbound)
	}
	if fw.Outbound[0].Host == "any" {
		t.Error("the allow-all outbound survived, which makes every compiled outbound rule dead weight")
	}
	if fw.Outbound[0].CIDR != "10.42.0.2/32" {
		t.Errorf("outbound rule = %+v", fw.Outbound[0])
	}
	// The routed-subnet rule keeps its local_cidr, or it silently does nothing
	// on a host with unsafe networks.
	if fw.Inbound[1].LocalCIDR != "192.168.50.0/24" {
		t.Errorf("local_cidr was dropped in rendering: %+v", fw.Inbound[1])
	}
}

// A policy replaces the role's rules rather than merging with them: two sources
// of firewall rules means two answers to "what may reach this host".
func TestPolicyReplacesTheRoleFirewall(t *testing.T) {
	rs := testRuleset()
	out, err := Render(Input{
		Paths: PathsFor("net"),
		Firewall: &Firewall{
			Inbound:  []Rule{{Port: "22", Proto: "tcp", Group: "ssh"}},
			Outbound: []Rule{{Port: "any", Proto: "any", Host: "any"}},
		},
		Policy:     &rs,
		ListenPort: 4242,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "ssh") {
		t.Errorf("the role's rules survived alongside the policy:\n%s", out)
	}
}

// The opt-in property: a network with no policy renders exactly the bytes it
// rendered before this package existed.
func TestNoPolicyChangesNothing(t *testing.T) {
	in := Input{
		Paths:      PathsFor("net"),
		Firewall:   DefaultFirewall(),
		ListenPort: 4242,
		Lighthouses: []Lighthouse{{
			VpnAddr: netip.MustParseAddr("10.42.0.1"), StaticAddrs: []string{"198.51.100.1:4242"},
		}},
	}
	withoutPolicy, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	fw := parsedFirewall(t, string(withoutPolicy))
	if len(fw.Outbound) != 1 || fw.Outbound[0].Host != "any" {
		t.Errorf("the no-policy path changed: %+v", fw.Outbound)
	}
	if len(fw.Inbound) != 0 {
		t.Errorf("the no-policy path grew inbound rules: %+v", fw.Inbound)
	}
}

// Nothing the compiler emits should reach the keys that short-circuit
// FirewallRule.isAny: a group, host or cidr of "any" matches every peer.
func TestRenderedPolicyRulesCarryNoIdentityKeys(t *testing.T) {
	body := renderPolicy(t)
	fw := parsedFirewall(t, body)
	for _, r := range fw.Inbound {
		if r.Host != "" || r.Group != "" || len(r.Groups) != 0 || r.CAName != "" || r.CASha != "" {
			t.Errorf("a compiled rule carries an identity key: %+v", r)
		}
	}
	// And the dead 'code' key is never emitted; nebula's own error says support
	// for it will be dropped because it has never been functional.
	if strings.Contains(body, "code:") {
		t.Errorf("the rendered config carries a code key:\n%s", body)
	}
}

// An empty policy in authoritative mode is a real posture: this host talks to
// nobody. It must render as empty lists rather than as absent keys, because an
// absent firewall key is not the same document.
func TestEmptyPolicyRendersClosed(t *testing.T) {
	rs := policy.Ruleset{}
	out, err := Render(Input{Paths: PathsFor("net"), Policy: &rs, ListenPort: 4242})
	if err != nil {
		t.Fatal(err)
	}
	fw := parsedFirewall(t, string(out))
	if len(fw.Inbound) != 0 || len(fw.Outbound) != 0 {
		t.Errorf("an empty policy rendered rules: %+v", fw)
	}
	if !strings.Contains(string(out), "inbound:") || !strings.Contains(string(out), "outbound:") {
		t.Errorf("the firewall keys are absent rather than empty:\n%s", out)
	}
}
