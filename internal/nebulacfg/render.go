// Package nebulacfg renders the nebula configuration Orbit owns on a managed
// host.
//
// TWO MODES, and the difference is about honesty rather than layout.
//
// ModeFragment is the original: Orbit writes /var/lib/nebula/config.d/50-orbit.yml
// into a directory and never touches the operator's own files. Nebula merges
// every .yml in a config DIRECTORY with mergo.WithAppendSlice, which means list
// keys — most importantly firewall rules — are CONCATENATED across files. Orbit
// therefore cannot see, cannot remove, and cannot report a rule an operator
// wrote in another file. Any policy Orbit states about such a host is a lower
// bound presented as an answer, which is tolerable while a human reads it and
// not tolerable the moment anything computes on it.
//
// ModeAuthoritative writes ONE COMPLETE FILE and nebula is pointed at that file
// rather than at a directory. That is not a nebula feature Orbit is bending:
// config.C.resolve stats the path it is given and, when it is not a directory,
// loads exactly that one file. There is no merge, so there is no second source
// of rules, and what Orbit reports about the host's policy is the whole of it.
//
// Authoritative mode is also what makes one machine on two networks work. Each
// network gets its own directory, its own complete file, its own tun.dev and its
// own listen.port, so two nebula processes coexist without either one's config
// directory bleeding into the other's.
//
// Nothing is deployed, so new hosts default to authoritative. Fragment stays
// supported as the escape hatch for a host that genuinely carries
// operator-authored nebula configuration, and the mode is stored on the host
// rather than inferred from where a file happens to sit — a caller has to be
// able to tell which of the two claims above it is being handed.
//
// /var/lib, not /etc, and the distinction is not cosmetic. Everything Orbit
// writes on a managed host — the certificate, the private key, the rendered
// fragment, and the previous generation kept for rollback — is RUNTIME STATE
// that the agent creates and replaces on its own schedule. On an image-based
// system (bootc, OSTree, Fedora CoreOS) /usr is read-only and /etc is an
// overlay the image reconciles on upgrade, so runtime state written there is
// fighting the image manager and can be reverted underneath a running host.
// /var is the location such systems guarantee is persistent and unmanaged.
//
// Operator-authored configuration is the opposite case and stays in /etc: it is
// authored once, read-only at runtime, and belongs to whoever builds the image.
// That is why the control plane reads /etc/orbit/orbit.env and writes
// /var/lib/orbit/ca.key. Nebula merges every .yml in a
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
	"path"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/griffithind/orbit/internal/policy"
)

// Render modes. These mirror store.ConfigMode* and the CHECK constraint in
// migrations/0001_initial.sql.
const ()

// Paths locates the files the agent manages alongside the configuration. They
// are absolute paths on the managed host, not on the control plane.
type Paths struct {
	CA   string // trust bundle, every non-retired CA
	Cert string // this host's certificate
	Key  string // this host's private key; written once at enrollment
}

// DefaultDir is where the agent keeps everything it owns on a managed host in
// FRAGMENT mode.
//
// Under /var/lib so an image-based system leaves it alone; see the package
// comment. systemd's StateDirectory=nebula creates exactly this path with the
// right ownership and is the idiomatic way to get it.
const DefaultDir = "/var/lib/nebula"

// DefaultPaths are the conventional fragment-mode locations. The agent owns
// these files entirely; the operator's own pki.* keys, if any, are overridden by
// ours because 50-orbit.yml sorts after a conventional 00-base.yml.
//
// The agent rewrites these to match its own -dir on receipt, so a control plane
// rendering one layout and an agent running another is not a mismatch — see
// internal/agent.localize.
func DefaultPaths() Paths {
	return Paths{
		CA:   DefaultDir + "/orbit-ca.crt",
		Cert: DefaultDir + "/orbit-host.crt",
		Key:  DefaultDir + "/orbit-host.key",
	}
}

// The authoritative-mode layout, one directory per network:
//
//	/var/lib/orbit/<slug>/
//	    nebula.yml     the COMPLETE config; nebula -config points at this file
//	    host.key       0600, written once at enrollment
//	    host.crt       rotated by renewal
//	    ca.crt         trust bundle, every non-retired CA
//	    agent.json     agent state
//	    .previous/     one generation, kept for rollback
//
// Keyed by SLUG rather than by network id, and that is the reason the slug had
// to become immutable: this path is written to disk on every managed host in the
// network, and a value that could change would not rename the directory, it
// would strand it and make every agent create a second one alongside.
//
// The private key stays a SEPARATE 0600 file rather than being inlined in the
// YAML. Nebula does accept inline PEM for pki.ca, pki.cert and pki.key — it
// checks the value for "-----BEGIN" — and inlining would make the whole
// configuration one atomic artifact, which is genuinely attractive. It is not
// worth it: every routine firewall push would then rewrite a file containing the
// host's private key, so the most frequent write on the box becomes the most
// dangerous one, and a botched write, a stray backup, or a log of the config
// body leaks the key. Separate files mean the key is written exactly once, at
// enrollment.
const (
	// AuthoritativeRoot is the parent of the per-network directories.
	AuthoritativeRoot = "/var/lib/orbit"

	// ConfigFileName is the complete configuration nebula is pointed at.
	ConfigFileName = "nebula.yml"
)

// DirFor is a network's directory on a managed host.
func DirFor(slug string) string { return path.Join(AuthoritativeRoot, slug) }

// The material filenames inside a per-network directory.
//
// They live here rather than beside the agent's layout because this package is
// what writes them into pki.ca, pki.cert and pki.key — the config nebula reads.
// The agent must put the files exactly where that config says, so the renderer
// owns the names and internal/agent/paths derives its own from these. They were
// two independent sets of string literals that happened to agree; a rename on
// one side would have signed every host a config pointing at a file the agent
// does not write, and nebula would fail to start fleet-wide with nothing naming
// the cause.
const (
	CAName   = "ca.crt"
	CertName = "host.crt"
	KeyName  = "host.key"
)

// PathsFor are the authoritative-mode material locations for a network.
func PathsFor(slug string) Paths {
	dir := DirFor(slug)
	return Paths{
		CA:   path.Join(dir, CAName),
		Cert: path.Join(dir, CertName),
		Key:  path.Join(dir, KeyName),
	}
}

// TunDevMaxLen is the longest interface name Linux will actually keep.
//
// overlay/tun_linux.go copies the configured name into a [16]byte with a bare
// copy() and returns no error, so the sixteenth byte onward is discarded in
// silence — and two names sharing the first fifteen characters become ONE
// device. That failure reports itself as two hosts that are both unreachable,
// with nothing anywhere naming the cause.
const TunDevMaxLen = 15

// TunDevSuggestion derives an interface name from a network slug.
//
// A suggestion: macOS requires utun[0-9]+ and warns "ignoring" for anything
// else, so the agent overrides this where the platform forbids it. What matters
// on the platform that DOES accept it is that two networks never derive the same
// name.
//
// Plain truncation would not give that. Slugs are unique, but their first
// fifteen characters are not — "production-cluster-eu" and
// "production-cluster-us" truncate to the same device — so the long case keeps
// ten characters of the slug for legibility and spends the remaining four on a
// hash of the whole thing. Deterministic, because the name has to be the same on
// every render or the agent sees a change on every poll.
func TunDevSuggestion(slug string) string {
	if len(slug) <= TunDevMaxLen {
		return slug
	}
	// FNV-1a, inline: a non-cryptographic hash is exactly right here (this is a
	// collision-avoidance tiebreak, not a security boundary) and it avoids
	// importing a hash package for four hex digits.
	var h uint32 = 2166136261
	for i := 0; i < len(slug); i++ {
		h ^= uint32(slug[i])
		h *= 16777619
	}
	return fmt.Sprintf("%s-%04x", strings.TrimRight(slug[:10], "-"), h&0xffff)
}

// Lighthouse is a lighthouse a host should know about.
type Lighthouse struct {
	// VpnAddr is the lighthouse's overlay address.
	VpnAddr netip.Addr
	// StaticAddrs are underlay "host:port" entries. A lighthouse with none is
	// unreachable for bootstrap and is skipped.
	StaticAddrs []string
}

// Input is everything needed to render a host's configuration.
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

	// Policy is this host's compiled network policy, and REPLACES Firewall when
	// set.
	//
	// Replaces rather than merges, because two sources of firewall rules means
	// two answers to "what may reach this host" and the whole point of a
	// compiled policy is that there is one. A network that adopts a policy stops
	// using its roles' rules; the roles keep supplying certificate groups.
	//
	// Rendered through FirewallFromPolicy, which is where Mode decides what may
	// honestly be claimed about the outbound direction.
	Policy *policy.Ruleset

	ListenHost string
	ListenPort int

	// Punchy defaults to enabled. There is no good reason to ship a managed
	// mesh with hole punching off.
	DisablePunchy bool

	// TunDisabled produces a lighthouse that needs no tun device and no root.
	TunDisabled bool

	// DNSDomain is the search suffix for this network, and Names is every
	// machine in it. Empty Names renders no dns section at all, so a network
	// that has not enabled it is byte-identical to what it was.
	DNSDomain string
	DNSListen netip.Addr
	Names     []Name

	// SoMark is nebula's packet mark, set only when this host has a default
	// route. Zero omits it.
	SoMark int

	// Serves are the prefixes THIS host is a gateway for, with their NAT
	// setting — the agent's instructions, not nebula's. Distinct from Routes,
	// which is what this host reaches through somebody else.
	Serves []Served

	// Routes are the external prefixes this host may reach through gateways in
	// the mesh, already grouped by prefix. Empty renders no unsafe_routes at
	// all.
	//
	// The gateway's own config does NOT list its routes here: it reaches them
	// on its own interfaces, and a route pointing at itself is a loop. The
	// caller filters, because only the caller knows which host it is rendering
	// for.
	Routes []Route

	// TunDev is the interface name, allocated per (host, network) so that two
	// nebula processes on one machine do not fight over one device.
	//
	// A SUGGESTION as far as the host is concerned, and the platforms are why.
	// Linux copies this into a [16]byte with a bare copy() and no error, so
	// anything over 15 characters is silently truncated and two long names
	// collide into one device. macOS requires utun[0-9]+, warns "ignoring" for
	// anything else, and lets the kernel choose. Orbit renders the field because
	// the value has to come from somewhere the two networks can differ; the
	// agent overrides it where the platform forbids it.
	//
	// Empty omits the key, leaving nebula's own default.
	TunDev string

	// TunMTU is the overlay MTU. Zero omits the key.
	TunMTU int

	// LighthouseInterval is how often a host reports to its lighthouses, in
	// seconds. Zero omits the key.
	LighthouseInterval int

	// LogLevel and LogFormat are emitted in authoritative mode only. In fragment
	// mode they are deliberately absent: 50-orbit.yml sorts after a conventional
	// 00-base.yml, so a scalar Orbit emits WINS, and emitting a log level there
	// would silently overwrite the operator's.
	LogLevel  string
	LogFormat string

	// Overrides are nebula settings Orbit does not model, merged last.
	//
	// Refused for the keys Orbit owns; see ValidateOverrides for which and why.
	Overrides map[string]any
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
	// Interval is omitted in fragment mode so nebula's own default applies and
	// an operator's 00-base.yml is not overridden by file order.
	Interval int `yaml:"interval,omitempty"`
}

type listenSection struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`

	// SoMark marks nebula's OWN outer packets so they are not routed back into
	// the tunnel they carry.
	//
	// Only meaningful with a default route, and that is the only time it is
	// emitted. With 0.0.0.0/0 pointing at the tun, nebula's UDP to the
	// lighthouse matches its own default route: the tunnel carries the packet
	// that carries the tunnel. The mark is what an `ip rule` uses to send
	// marked traffic to the real gateway instead.
	//
	// Linux only — nebula implements SO_MARK in udp_linux.go and has no darwin
	// equivalent, which is why a Mac can USE routes but not a default one.
	SoMark int `yaml:"so_mark,omitempty"`
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
	// Dev and MTU are omitted when unset so nebula's defaults apply. Dev is a
	// suggestion the agent may override; see Input.TunDev.
	Dev string `yaml:"dev,omitempty"`
	MTU int    `yaml:"mtu,omitempty"`

	// UnsafeRoutes reaches things that cannot run nebula. Omitted entirely when
	// there are none, so an ordinary host's config is unchanged by the feature
	// existing.
	UnsafeRoutes []unsafeRoute `yaml:"unsafe_routes,omitempty"`
}

// unsafeRoute is one prefix and the gateways that reach it.
//
// One entry per PREFIX, not per gateway: nebula takes a list of `via` and load
// balances across it by weight, falling to a survivor when one stops answering.
// Rendering one entry per gateway would produce a config nebula accepts and
// treats as a single path, quietly losing the redundancy.
type unsafeRoute struct {
	Route string     `yaml:"route"`
	Via   []routeVia `yaml:"via"`
	MTU   int        `yaml:"mtu,omitempty"`
	// Install is a pointer so `false` is emitted. Nebula defaults it to true,
	// so omitting a false would install a route the operator asked to keep out
	// of the system routing table.
	Install *bool `yaml:"install,omitempty"`
}

type routeVia struct {
	Gateway string `yaml:"gateway"`
	// Weight is omitted at 1, which is nebula's default for an unweighted
	// gateway, so the common case renders as the documentation writes it.
	Weight int `yaml:"weight,omitempty"`
}

type loggingSection struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type document struct {
	PKI           pkiSection        `yaml:"pki"`
	StaticHostMap staticHostMap     `yaml:"static_host_map"`
	Lighthouse    lighthouseSection `yaml:"lighthouse"`
	Listen        listenSection     `yaml:"listen"`
	Punchy        punchySection     `yaml:"punchy"`
	Relay         relaySection      `yaml:"relay"`
	Tun           tunSection        `yaml:"tun"`
	// Logging is authoritative-mode only; nil omits the section entirely.
	Logging  *loggingSection `yaml:"logging,omitempty"`
	Firewall *Firewall       `yaml:"firewall"`

	// Orbit is what the AGENT must do that nebula does not: enable forwarding,
	// NAT a prefix. Nebula never reads it — config.C keeps every key in a map
	// and only looks up the ones it knows, so an unrecognised top-level section
	// is inert.
	//
	// In the SAME document on purpose. It is signed with everything else, so
	// instructions to change a machine's firewall arrive with the same proof as
	// its certificate paths and cannot be substituted independently. A second
	// file would need its own signature, its own delivery and its own
	// divergence check, and would eventually disagree with this one.
	Orbit *orbitSection `yaml:"orbit,omitempty"`
}

// orbitSection is the agent's instructions, ignored by nebula.
type orbitSection struct {
	// Forward is true when this host is a gateway for something.
	Forward bool `yaml:"forward,omitempty"`

	// DNS is the name table this host answers locally, and the domain it
	// searches. Nil when the network has no names to serve.
	DNS *dnsSection `yaml:"dns,omitempty"`

	// ExitNode is true when this host reaches 0.0.0.0/0 through the mesh.
	//
	// It is what a platform acts on to keep nebula's own UDP out of the tunnel
	// it carries: on darwin the agent pins the socket to the physical default
	// route's interface, on Linux it installs the ip rule that listen.so_mark
	// exists to be matched by. Nebula reads neither.
	ExitNode bool `yaml:"exit_node,omitempty"`

	// Masquerade lists prefixes whose forwarded traffic is NATed leaving this
	// host. Per prefix rather than per host: a gateway can legitimately want
	// NAT for 0.0.0.0/0 and not for a LAN it also serves.
	Masquerade []string `yaml:"masquerade,omitempty"`
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

const authoritativeHeader = `# Managed by Orbit. Do not edit.
#
# This is the COMPLETE nebula configuration for this network. Nebula is
# pointed at this file, not at a directory, so nothing else is merged in:
# what is here is everything that applies, and the firewall rules below are
# the whole policy rather than an addition to somebody else's.
#
# It is regenerated on every configuration change and overwritten without
# warning. Settings Orbit does not model are set through the control plane's
# per-host overrides, which are merged into this file when it is rendered.
`

// Defaults for authoritative mode.
//
// These matter more than defaults usually do: in authoritative mode there is no
// second file, so whatever an operator would have put in 00-base.yml either
// appears here or does not appear at all. They are deliberately nebula's own
// defaults, stated explicitly rather than left implicit — the value of writing
// them down is that this file is the documentation of what the host is running,
// and a key that is absent forces a reader to know nebula's source to answer
// "what MTU is this host using".
//
// Authoritative does not mean Orbit restates every nebula default; it means
// Orbit is the only FILE. Keys neither set here nor overridden still fall back
// to nebula's built-ins, which is correct and is what keeps this list short
// enough to review.
const (
	// Six times slower than nebula's own default of 10 (lighthouse.go:228,
	// c.GetInt("lighthouse.interval", 10)), and deliberately so: a managed fleet
	// reports to lighthouses it was told about, on a schedule the control plane
	// sets, and 10s of keepalive per host per lighthouse is bandwidth spent to
	// shorten a roam that Orbit already re-renders for.
	//
	// The comment here used to read "nebula's own default", which was false and
	// made this line look like a no-op. A host that roams takes up to a minute
	// to become findable at its new address; that is the trade.
	defaultLighthouseInterval = 60     // seconds
	defaultTunMTU             = 1300   // nebula's own default
	defaultLogLevel           = "info" // the level an operator changes most often
	defaultLogFormat          = "text"
)

// Render produces the managed configuration.
func Render(in Input) ([]byte, error) {
	if in.Paths.CA == "" || in.Paths.Cert == "" || in.Paths.Key == "" {
		return nil, fmt.Errorf("incomplete paths: %+v", in.Paths)
	}
	if in.ListenHost == "" {
		// "::" listens on both families where the platform supports it, which
		// is what a v2-certificate mesh needs.
		in.ListenHost = "::"
	}
	if in.LighthouseInterval == 0 {
		in.LighthouseInterval = defaultLighthouseInterval
	}
	if in.TunMTU == 0 {
		in.TunMTU = defaultTunMTU
	}
	if in.LogLevel == "" {
		in.LogLevel = defaultLogLevel
	}
	if in.LogFormat == "" {
		in.LogFormat = defaultLogFormat
	}

	fw := in.Firewall
	if fw == nil {
		fw = DefaultFirewall()
	}
	if in.Policy != nil {
		fw = FirewallFromPolicy(*in.Policy)
	}
	fw = widenForServedRoutes(fw, in.Serves)

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
			Interval:     in.LighthouseInterval,
		},
		Listen: listenSection{
			SoMark: in.SoMark, Host: in.ListenHost, Port: in.ListenPort},
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
		Tun: tunSection{
			Disabled:     in.TunDisabled,
			Dev:          in.TunDev,
			MTU:          in.TunMTU,
			UnsafeRoutes: renderRoutes(in.Routes),
		},
		Firewall: fw,
		Orbit:    renderOrbit(in.Serves, hasDefault(in.Routes), renderDNS(in.DNSDomain, in.DNSListen, in.Names)),
	}
	if in.LogLevel != "" || in.LogFormat != "" {
		doc.Logging = &loggingSection{Level: in.LogLevel, Format: in.LogFormat}
	}

	// Marshal through a node tree rather than straight to bytes, so overrides
	// can be merged into the structure instead of concatenated after it. The
	// tree preserves the struct's field order, and every value the merge adds is
	// emitted with sorted keys, so the output stays byte-identical for identical
	// inputs — which is the property the agent's "has anything changed?" hash
	// depends on.
	var root yaml.Node
	if err := root.Encode(doc); err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	if len(in.Overrides) > 0 {
		if err := ValidateOverrides(in.Overrides); err != nil {
			return nil, err
		}
		if err := applyOverrides(&root, in.Overrides); err != nil {
			return nil, err
		}
	}

	body, err := yaml.Marshal(&root)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	return append([]byte(authoritativeHeader), body...), nil
}

// Route is one prefix and the gateways offering it, as the caller assembled it.
type Route struct {
	Prefix   netip.Prefix
	Gateways []Gateway

	// MTU and Install come from the route, not the gateway: a prefix has one
	// answer for both however many machines reach it.
	MTU     int
	Install bool
}

// Served is one prefix this host forwards for.
type Served struct {
	Prefix     netip.Prefix
	Masquerade bool
}

// Gateway is one machine offering a prefix, and its share of the traffic.
type Gateway struct {
	Addr   netip.Addr
	Weight int
}

// renderRoutes turns the caller's prefixes into nebula's unsafe_routes.
//
// Gateways with no address are dropped rather than rendered as an empty string:
// nebula would refuse the config, and refusing the whole configuration because
// one gateway is half-enrolled would take down a host that has nothing to do
// with it. A prefix left with no gateways is dropped whole, for the same
// reason — an unsafe_route with an empty via list is a config error, not a
// route that goes nowhere.
func renderRoutes(routes []Route) []unsafeRoute {
	out := make([]unsafeRoute, 0, len(routes))
	for _, r := range routes {
		via := make([]routeVia, 0, len(r.Gateways))
		for _, g := range r.Gateways {
			if !g.Addr.IsValid() {
				continue
			}
			w := g.Weight
			if w == 1 {
				w = 0 // omitted; nebula's default for an unweighted gateway
			}
			via = append(via, routeVia{Gateway: g.Addr.String(), Weight: w})
		}
		if len(via) == 0 {
			continue
		}
		for _, p := range splitDefault(r.Prefix) {
			e := unsafeRoute{Route: p, Via: via, MTU: r.MTU}
			if !r.Install {
				// Only when false. Nebula defaults to true, so emitting it always
				// would be noise in every config that never wanted the knob.
				no := false
				e.Install = &no
			}
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dnsSection is the name table, carried in the signed configuration.
//
// WHY HERE AND NOT A RESOLVER SOMEWHERE IN THE MESH.
//
// Nebula can run a DNS server on a lighthouse, answering from its hostmap. That
// puts every lookup in the fleet through one machine over the overlay, and its
// failure mode is a mesh that works while nothing can be found by name.
//
// Orbit had a better channel already built: a signed configuration with an
// epoch, delivered everywhere, reverted automatically when it breaks. A name
// table riding in it is answered locally with no round trip and no single point
// of failure, and a name carries the same proof as the certificate paths beside
// it — the control plane cannot mint a name it has not signed for.
//
// A LIST, not a map. Two control planes rendering the same network must produce
// identical bytes because the result is signed, and a map's marshalling order is
// not part of any guarantee worth resting a digest on.
type dnsSection struct {
	// Domain is the search suffix, so `ssh laptop` works and
	// `laptop.<network>.orbit` is what it means.
	Domain string `yaml:"domain,omitempty"`

	// Listen is where this host's resolver binds: its own overlay address.
	//
	// Its OWN address rather than a loopback, because every loopback worth
	// having is already taken on some platform — 127.0.0.53 is systemd-resolved,
	// 127.0.0.1:53 is whatever else the machine runs — and a resolver that fails
	// to bind is a machine that cannot resolve anything. The overlay address is
	// unique by construction, reachable from the host itself, and already in the
	// certificate.
	Listen string `yaml:"listen,omitempty"`

	// Hosts is every reachable machine in this network, this one included: a
	// host that cannot resolve its own name is a surprise nobody needs.
	Hosts []dnsHost `yaml:"hosts,omitempty"`
}

// dnsHost is one machine and every overlay address it answers on.
type dnsHost struct {
	Name  string   `yaml:"name"`
	Addrs []string `yaml:"addrs"`
}

// Name is one machine's name and one of its overlay addresses, as the caller
// assembled it. One entry per address; a dual-stack host has two.
type Name struct {
	Name string
	Addr netip.Addr
}

// renderDNS groups the caller's rows into one entry per machine.
//
// Grouping here rather than in SQL because the answer to an A query is every
// address that machine has, and a resolver that returned one of them would work
// until the day the other was the reachable one.
func renderDNS(domain string, listen netip.Addr, names []Name) *dnsSection {
	if len(names) == 0 || !listen.IsValid() {
		return nil
	}
	out := &dnsSection{Domain: domain, Listen: netip.AddrPortFrom(listen, 53).String()}
	for _, n := range names {
		if n.Name == "" || !n.Addr.IsValid() {
			continue
		}
		if k := len(out.Hosts); k > 0 && out.Hosts[k-1].Name == n.Name {
			out.Hosts[k-1].Addrs = append(out.Hosts[k-1].Addrs, n.Addr.String())
			continue
		}
		out.Hosts = append(out.Hosts, dnsHost{Name: n.Name, Addrs: []string{n.Addr.String()}})
	}
	if len(out.Hosts) == 0 {
		return nil
	}
	return out
}

// splitDefault turns a default route into the two halves that cover the same space
// without being a default route.
//
// A host already has a default route, and a second one is not a route — it is a
// collision. Darwin's RTM_ADD returns EEXIST and nebula logs "identical route already
// exists" and carries on doing nothing, so the exit node silently never works. The halves
// are each more specific, so longest-prefix match prefers them over whatever the DHCP
// lease installed, with nothing removed and nothing to restore on the way out: teardown
// deletes two routes rather than repairing one it clobbered.
//
// Every implementation lands here — wg-quick's darwin path, ZeroTier's _forkTarget,
// Tailscale. It is applied on all platforms rather than only the ones that would break,
// because "more specific than the default" is the behaviour we want everywhere and one
// rendering is one thing to reason about.
func splitDefault(p netip.Prefix) []string {
	if p.Bits() != 0 {
		return []string{p.String()}
	}
	if p.Addr().Is4() {
		return []string{"0.0.0.0/1", "128.0.0.0/1"}
	}
	return []string{"::/1", "8000::/1"}
}

// widenForServedRoutes makes an omitted local_cidr mean what it reads as.
//
// Nebula's firewallLocalCIDR.addRule (firewall.go:893): an empty local_cidr is
// "any address" ONLY while the host's certificate carries no unsafe networks.
// Once a host becomes a gateway, Orbit puts its routes into that certificate
// (enroll/service.go:660) and every inbound rule without an explicit local_cidr
// silently narrows to the host's own overlay addresses — so forwarded traffic
// is dropped by nebula before it reaches the tun.
//
// The cruel part is the timing: the narrowing arrives with the NEXT certificate,
// minutes to hours after `orbit route add`, so the cause and the symptom are far
// apart and the symptom looks like a certificate problem.
//
// So each such rule is DUPLICATED, once per served prefix, with local_cidr set.
// The original is kept: nebula narrows it to the host's own addresses, which is
// still wanted. The result is that an omitted local_cidr covers "wherever this
// host answers", which is what a reader assumes it means.
//
// The policy compiler already did this for selectors naming a routed subnet
// (policy/compile.go:225). Roles — the DEFAULT firewall source — did not, and a
// role's rules are free-form JSON where LocalCIDR is optional and unchecked.
// See docs/adr/0021-gateway-reachability-is-derived-from-routes.md.
func widenForServedRoutes(fw *Firewall, serves []Served) *Firewall {
	if fw == nil || len(serves) == 0 {
		return fw
	}
	// Inbound only. Outbound local_cidr matches this host's own source address,
	// which forwarding does not change.
	var extra []Rule
	for _, r := range fw.Inbound {
		if r.LocalCIDR != "" {
			continue // the author said where this applies; do not second-guess it
		}
		for _, sv := range serves {
			widened := r
			widened.LocalCIDR = sv.Prefix.String()
			extra = append(extra, widened)
		}
	}
	if len(extra) == 0 {
		return fw
	}
	out := *fw
	out.Inbound = append(append([]Rule{}, fw.Inbound...), extra...)
	return &out
}

// hasDefault reports whether any of these routes is a default route.
//
// Derived from the rendered routes rather than passed in beside them, so the flag and the
// routes cannot disagree: a host told it has an exit node but given no default route, or
// the reverse, is a machine whose network behaviour nobody can predict from its config.
func hasDefault(routes []Route) bool {
	for _, r := range routes {
		if r.Prefix.Bits() == 0 {
			return true
		}
	}
	return false
}

// renderOrbit describes what the agent must do to the host.
//
// Nil when this host serves nothing, so an ordinary machine's configuration is
// byte-identical to what it was before routes existed — which is what keeps a
// feature nobody uses from re-applying every config in a fleet.
func renderOrbit(serves []Served, exitNode bool, dns *dnsSection) *orbitSection {
	if len(serves) == 0 && !exitNode && dns == nil {
		return nil
	}
	out := &orbitSection{Forward: len(serves) > 0, ExitNode: exitNode, DNS: dns}
	for _, s := range serves {
		if s.Masquerade {
			out.Masquerade = append(out.Masquerade, s.Prefix.String())
		}
	}
	return out
}
