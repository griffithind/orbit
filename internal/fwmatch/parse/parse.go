// Package parse turns a nebula configuration into fwmatch rules.
//
// Split from fwmatch so that fwmatch itself imports nothing. The matching half
// is referenced by internal/wire, which every API client embeds, and two
// Decision fields there were enough to link nebula, gvisor and wireguard into
// internal/adminclient — a package that makes HTTP requests and nothing else.
//
// The parsing genuinely needs nebula and should: AddFirewallRulesFromConfig is
// what keeps Orbit from re-implementing the parser. Confining it here means the
// cost is paid by the two callers that parse, not by everything that names a
// Decision.
package parse

import (
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"

	"github.com/griffithind/orbit/internal/fwmatch"
)

// fwmatch redeclares nebula's firewall constants so that it imports nothing.
// These assertions keep the two sets honest: if nebula ever renumbers one, THIS
// package stops compiling rather than fwmatch silently disagreeing with the
// firewall it claims to model.
//
// Subtraction in both directions, because an unsigned conversion only rejects
// the negative one — a single direction would catch a decrease and miss an
// increase.
const (
	_ = uint8(fwmatch.ProtoAny - firewall.ProtoAny)
	_ = uint8(firewall.ProtoAny - fwmatch.ProtoAny)
	_ = uint8(fwmatch.ProtoICMP - firewall.ProtoICMP)
	_ = uint8(firewall.ProtoICMP - fwmatch.ProtoICMP)
	_ = uint8(fwmatch.ProtoTCP - firewall.ProtoTCP)
	_ = uint8(firewall.ProtoTCP - fwmatch.ProtoTCP)
	_ = uint8(fwmatch.ProtoUDP - firewall.ProtoUDP)
	_ = uint8(firewall.ProtoUDP - fwmatch.ProtoUDP)
	_ = uint8(fwmatch.ProtoICMPv6 - firewall.ProtoICMPv6)
	_ = uint8(firewall.ProtoICMPv6 - fwmatch.ProtoICMPv6)

	_ = uint32(fwmatch.PortAny - firewall.PortAny)
	_ = uint32(firewall.PortAny - fwmatch.PortAny)
	_ = uint32(fwmatch.PortFragment - firewall.PortFragment)
	_ = uint32(firewall.PortFragment - fwmatch.PortFragment)
)

// ruleCollector is a nebula.FirewallInterface that records instead of enforcing.
type ruleCollector struct{ rules []fwmatch.Rule }

var _ nebula.FirewallInterface = (*ruleCollector)(nil)

func (rc *ruleCollector) AddRule(incoming bool, proto uint8, startPort, endPort int32,
	groups []string, host, cidr, localCidr, caName, caSha string) error {
	rc.rules = append(rc.rules, fwmatch.Rule{
		Incoming: incoming, Proto: proto, StartPort: startPort, EndPort: endPort,
		Groups: slices.Clone(groups), Host: host, CIDR: cidr,
		LocalCIDR: localCidr, CAName: caName, CASha: caSha,
	})
	return nil
}

// LoadRules reads the firewall out of a configuration on disk.
//
// path is Layout.NebulaConfigArg — a file in authoritative mode and a directory
// in fragment mode — so in fragment mode this returns the operator's rules
// alongside Orbit's. That is deliberate: the question is what is in force, not
// what Orbit believes it sent.
func LoadRules(path string) (inbound, outbound []fwmatch.Rule, err error) {
	c := config.NewC(quiet())
	if err := c.Load(path); err != nil {
		return nil, nil, fmt.Errorf("load %s: %w", path, err)
	}
	return collect(c)
}

// LoadRulesFromString is the same over a configuration held in memory, which is
// how the control plane asks about a ruleset it just compiled.
func LoadRulesFromString(raw string) (inbound, outbound []fwmatch.Rule, err error) {
	c := config.NewC(quiet())
	if err := c.LoadString(raw); err != nil {
		return nil, nil, fmt.Errorf("parse configuration: %w", err)
	}
	return collect(c)
}

func collect(c *config.C) (inbound, outbound []fwmatch.Rule, err error) {
	var in, out ruleCollector
	if err := nebula.AddFirewallRulesFromConfig(quiet(), true, c, &in); err != nil {
		return nil, nil, fmt.Errorf("firewall.inbound: %w", err)
	}
	if err := nebula.AddFirewallRulesFromConfig(quiet(), false, c, &out); err != nil {
		return nil, nil, fmt.Errorf("firewall.outbound: %w", err)
	}
	return in.rules, out.rules, nil
}

// quiet discards nebula's config logging, which is at info and would otherwise
// land in the middle of a diagnosis.
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
