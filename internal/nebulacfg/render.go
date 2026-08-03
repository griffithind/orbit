// Package nebulacfg renders the configuration fragment Orbit owns on a managed
// host.
//
// Orbit writes exactly one file, /etc/nebula/config.d/50-orbit.yml, and never
// touches the operator's own configuration. Nebula merges every .yml in a
// config directory with mergo.WithAppendSlice (config/config.go parse), so:
//
//   - scalar keys Orbit sets win or lose by file order, and
//   - list keys, most importantly firewall rules, are CONCATENATED.
//
// That second point is the one that surprises people. An operator rule and an
// Orbit rule both apply; there is no "deny by omission" and no way for this
// fragment to remove a rule the operator wrote. Anything that must be
// guaranteed absent has to be absent from every file.
//
// Output is deterministic: the same inputs always produce byte-identical YAML,
// so an agent can hash the fragment to decide whether anything actually
// changed, and a diff in review means a real change.
package nebulacfg

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"

	"go.yaml.in/yaml/v3"
)

// Paths locates the files the agent manages alongside the fragment. They are
// absolute paths on the managed host, not on the control plane.
type Paths struct {
	CA   string // trust bundle, every non-retired CA
	Cert string // this host's certificate
	Key  string // this host's private key; written once at enrollment
}

// DefaultPaths are the conventional locations. The agent owns these files
// entirely; the operator's own pki.* keys, if any, are overridden by ours
// because 50-orbit.yml sorts after a conventional 00-base.yml.
func DefaultPaths() Paths {
	return Paths{
		CA:   "/etc/nebula/orbit-ca.crt",
		Cert: "/etc/nebula/orbit-host.crt",
		Key:  "/etc/nebula/orbit-host.key",
	}
}

// Lighthouse is a lighthouse a host should know about.
type Lighthouse struct {
	// VpnAddr is the lighthouse's overlay address.
	VpnAddr netip.Addr
	// StaticAddrs are underlay "host:port" entries. A lighthouse with none is
	// unreachable for bootstrap and is skipped.
	StaticAddrs []string
}

// Input is everything needed to render a host's fragment.
type Input struct {
	Paths Paths

	// AmLighthouse and AmRelay come from the host record.
	AmLighthouse bool
	AmRelay      bool

	// Lighthouses excludes this host when it is itself a lighthouse: nebula
	// rejects a configuration that lists the local node as a lighthouse to
	// query.
	Lighthouses []Lighthouse

	// Relays are overlay addresses of hosts willing to relay for this one.
	Relays []netip.Addr

	// Blocklist is the set of revoked certificate fingerprints still worth
	// distributing, i.e. those whose certificates have not yet expired.
	Blocklist []string

	// Firewall comes from the host's role. Nil yields the conservative default:
	// all outbound allowed, no inbound.
	Firewall *Firewall

	ListenHost string
	ListenPort int

	// Punchy defaults to enabled. There is no good reason to ship a managed
	// mesh with hole punching off.
	DisablePunchy bool

	// TunDisabled produces a lighthouse that needs no tun device and no root.
	TunDisabled bool
}

// Firewall mirrors nebula's firewall configuration. Rules are appended to
// whatever the operator's own files declare, never substituted for them.
type Firewall struct {
	Inbound  []Rule `json:"inbound"  yaml:"inbound"`
	Outbound []Rule `json:"outbound" yaml:"outbound"`
}

// Rule is one nebula firewall rule. Field names and semantics match
// nebula's firewall.go convertRule; a key nebula does not recognise is a
// silently ignored rule, so this struct is the schema of record for what a
// role may express.
type Rule struct {
	// Port accepts a number, a "22-80" range, "any", or "fragment".
	Port  string `json:"port"            yaml:"port"`
	Proto string `json:"proto"           yaml:"proto"`

	// Code is the ICMP code, only meaningful with proto: icmp.
	Code string `json:"code,omitempty" yaml:"code,omitempty"`

	Host      string   `json:"host,omitempty"       yaml:"host,omitempty"`
	Group     string   `json:"group,omitempty"      yaml:"group,omitempty"`
	Groups    []string `json:"groups,omitempty"     yaml:"groups,omitempty"`
	CIDR      string   `json:"cidr,omitempty"       yaml:"cidr,omitempty"`
	LocalCIDR string   `json:"local_cidr,omitempty" yaml:"local_cidr,omitempty"`
	CAName    string   `json:"ca_name,omitempty"    yaml:"ca_name,omitempty"`
	CASha     string   `json:"ca_sha,omitempty"     yaml:"ca_sha,omitempty"`
}

// DefaultFirewall allows all outbound traffic and no inbound.
//
// Deny-by-default inbound is the right posture, but it does mean a host with no
// role cannot be reached at all, including by ICMP. That is intentional: a host
// that is unreachable is a visible misconfiguration, whereas a host that is
// reachable by accident is an invisible one.
func DefaultFirewall() *Firewall {
	return &Firewall{
		Outbound: []Rule{{Port: "any", Proto: "any", Host: "any"}},
		Inbound:  []Rule{},
	}
}

// ParseFirewall decodes a role's stored jsonb rules.
func ParseFirewall(raw []byte) (*Firewall, error) {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return DefaultFirewall(), nil
	}
	var fw Firewall
	if err := json.Unmarshal(raw, &fw); err != nil {
		return nil, fmt.Errorf("parse firewall rules: %w", err)
	}
	if fw.Outbound == nil {
		fw.Outbound = []Rule{}
	}
	if fw.Inbound == nil {
		fw.Inbound = []Rule{}
	}
	return &fw, nil
}

// pkiSection is emitted for every host.
type pkiSection struct {
	CA   string `yaml:"ca"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// Blocklist is always present, even when empty, so that removing the last
	// entry actually clears it rather than leaving a stale list from a previous
	// fragment merged in from elsewhere.
	Blocklist []string `yaml:"blocklist"`
	// DisconnectInvalid is always true. Without it an expired certificate does
	// not tear down a live tunnel (connection_manager.go isInvalidCertificate),
	// which silently disables the expiry backstop that bounds revocation for a
	// partitioned host. See docs/revocation.md.
	DisconnectInvalid bool `yaml:"disconnect_invalid"`
}

type lighthouseSection struct {
	AmLighthouse bool     `yaml:"am_lighthouse"`
	Hosts        []string `yaml:"hosts"`
}

type listenSection struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type punchySection struct {
	Punch   bool `yaml:"punch"`
	Respond bool `yaml:"respond"`
}

type relaySection struct {
	AmRelay   bool     `yaml:"am_relay"`
	UseRelays bool     `yaml:"use_relays"`
	Relays    []string `yaml:"relays"`
}

type tunSection struct {
	Disabled bool `yaml:"disabled"`
}

type document struct {
	PKI           pkiSection        `yaml:"pki"`
	StaticHostMap staticHostMap     `yaml:"static_host_map"`
	Lighthouse    lighthouseSection `yaml:"lighthouse"`
	Listen        listenSection     `yaml:"listen"`
	Punchy        punchySection     `yaml:"punchy"`
	Relay         relaySection      `yaml:"relay"`
	Tun           tunSection        `yaml:"tun"`
	Firewall      *Firewall         `yaml:"firewall"`
}

// staticHostMap marshals with sorted keys. Go map iteration order is random,
// and yaml.v3 does not sort, so without this the same inputs would produce
// different bytes on every render and every agent would see a spurious change.
type staticHostMap map[string][]string

func (m staticHostMap) MarshalYAML() (any, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	node := &yaml.Node{Kind: yaml.MappingNode}
	for _, k := range keys {
		kn := &yaml.Node{Kind: yaml.ScalarNode, Value: k}
		// Quote the key: an overlay address is not a YAML scalar we want
		// interpreted (a bare 10.42.0.1 is fine, but consistency avoids
		// surprises with IPv6 and with addresses that look like sexagesimals).
		kn.Style = yaml.DoubleQuotedStyle

		vn := &yaml.Node{Kind: yaml.SequenceNode}
		for _, v := range m[k] {
			vn.Content = append(vn.Content, &yaml.Node{
				Kind: yaml.ScalarNode, Value: v, Style: yaml.DoubleQuotedStyle,
			})
		}
		node.Content = append(node.Content, kn, vn)
	}
	return node, nil
}

const header = `# Managed by Orbit. Do not edit.
#
# This file is regenerated on every configuration change and overwritten
# without warning. Put local settings in another file in this directory
# (for example 00-base.yml); nebula merges them all.
#
# Note that nebula APPENDS list values across files rather than replacing
# them, so firewall rules here are added to yours, not substituted for them.
`

// Render produces the managed fragment.
func Render(in Input) ([]byte, error) {
	if in.Paths.CA == "" || in.Paths.Cert == "" || in.Paths.Key == "" {
		return nil, fmt.Errorf("incomplete paths: %+v", in.Paths)
	}
	if in.ListenHost == "" {
		// "::" listens on both families where the platform supports it, which
		// is what a v2-certificate mesh needs.
		in.ListenHost = "::"
	}

	fw := in.Firewall
	if fw == nil {
		fw = DefaultFirewall()
	}

	shm := staticHostMap{}
	lhHosts := []string{}
	for _, lh := range in.Lighthouses {
		if !lh.VpnAddr.IsValid() || len(lh.StaticAddrs) == 0 {
			// A lighthouse with no underlay address cannot be reached for
			// bootstrap. Skipping it is better than emitting an entry that
			// makes the host retry forever against nothing.
			continue
		}
		addr := lh.VpnAddr.String()
		addrs := append([]string(nil), lh.StaticAddrs...)
		sort.Strings(addrs)
		shm[addr] = addrs
		lhHosts = append(lhHosts, addr)
	}
	sort.Strings(lhHosts)

	if in.AmLighthouse {
		// A lighthouse must not list itself, and generally should not query
		// other lighthouses.
		lhHosts = []string{}
	}

	relays := make([]string, 0, len(in.Relays))
	for _, r := range in.Relays {
		if r.IsValid() {
			relays = append(relays, r.String())
		}
	}
	sort.Strings(relays)

	blocklist := append([]string(nil), in.Blocklist...)
	sort.Strings(blocklist)
	if blocklist == nil {
		blocklist = []string{}
	}

	doc := document{
		PKI: pkiSection{
			CA:                in.Paths.CA,
			Cert:              in.Paths.Cert,
			Key:               in.Paths.Key,
			Blocklist:         blocklist,
			DisconnectInvalid: true,
		},
		StaticHostMap: shm,
		Lighthouse: lighthouseSection{
			AmLighthouse: in.AmLighthouse,
			Hosts:        lhHosts,
		},
		Listen: listenSection{Host: in.ListenHost, Port: in.ListenPort},
		Punchy: punchySection{
			Punch:   !in.DisablePunchy,
			Respond: !in.DisablePunchy,
		},
		Relay: relaySection{
			AmRelay: in.AmRelay,
			// A relay does not itself use relays; nebula forces this too
			// (relay_manager.go reload), but being explicit keeps the rendered
			// config honest about what the host will actually do.
			UseRelays: !in.AmRelay,
			Relays:    relays,
		},
		Tun:      tunSection{Disabled: in.TunDisabled},
		Firewall: fw,
	}

	var out []byte
	out = append(out, header...)

	body, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return append(out, body...), nil
}
