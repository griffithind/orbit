package agent

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Host state: the things a gateway must be true of its own kernel.
//
// Nebula moves packets between the overlay and its tun device. It does not
// enable IP forwarding and it does not NAT — a gateway that forwards for a LAN
// needs both, and until now the agent touched no host state at all.
//
// WHAT MAKES THIS DIFFERENT FROM EVERY OTHER THING THE AGENT WRITES.
//
// A config file is replaced wholesale and the previous one is gone. Firewall
// rules are not: they live in a table somebody else also writes to, they
// survive the process that made them, and a half-removed set is worse than
// either state. So the rule here is ownership, not bookkeeping:
//
//	Own a whole CONTAINER — an nftables table, a pf anchor — never individual
//	rules inside somebody else's.
//
// Then removal is one operation that cannot half-succeed, and it works even if
// the rules were edited, even if the agent forgot it made them, even if the
// state file is gone. `nft destroy table inet orbit` needs no memory of what is
// in the table.
//
// A state file is not enough on its own and this deliberately does not keep
// one. It can be lost, it says nothing about a rule somebody has since changed,
// and reconciling against it would trust the record over the machine. The
// marker is on the object.

// TableName is the container Orbit owns on a gateway, and the reason removal is
// one operation rather than a list of them.
//
// Named here rather than beside the Linux implementation because `orbit agent
// uninstall` prints it as the manual fallback, and that message should be the
// same string on every platform the CLI is built for — including the ones that
// cannot create it.
const TableName = "orbit"

// HostState is what the agent must make true. It is DESIRED state, applied
// idempotently: the implementation replaces its whole container every time
// rather than diffing, because a diff is where partial application hides.
type HostState struct {
	// Forward enables IP forwarding. Needed by any gateway, because the kernel
	// drops packets not addressed to it otherwise, silently.
	Forward bool

	// Masquerade are prefixes whose forwarded traffic is NATed on the way out.
	//
	// Per prefix, not per host: 0.0.0.0/0 needs it because the internet cannot
	// route back to an overlay address, and a LAN prefix usually does not
	// because the far side can be told a static route and the operator would
	// rather see real source addresses in their own logs.
	Masquerade []netip.Prefix

	// TunDev is the interface forwarded traffic arrives on, used to scope rules
	// so they cannot match traffic that has nothing to do with Orbit.
	TunDev string
}

// Empty reports whether there is nothing to do.
//
// A machine that is not a gateway has no host state, and the agent must then
// REMOVE anything it left behind rather than skip — a machine that stops being
// a gateway must stop forwarding.
func (h HostState) Empty() bool {
	return !h.Forward && len(h.Masquerade) == 0
}

// String is a stable description, used to decide whether anything changed.
//
// Sorted, so two renderings of the same state compare equal and the agent does
// not rewrite the firewall on every poll for no reason.
func (h HostState) String() string {
	nets := make([]string, 0, len(h.Masquerade))
	for _, p := range h.Masquerade {
		nets = append(nets, p.String())
	}
	sort.Strings(nets)
	return fmt.Sprintf("forward=%v tun=%s masquerade=[%s]",
		h.Forward, h.TunDev, strings.Join(nets, ","))
}

// HostConfigurer applies host state. One per platform.
type HostConfigurer interface {
	// Apply makes the state true, replacing whatever was there before. It must
	// be safe to call repeatedly with the same state.
	Apply(HostState) error

	// Remove takes away everything this agent installed, whether or not it
	// still knows what that was. Called on uninstall and whenever a machine
	// stops being a gateway.
	Remove() error

	// Describe names the mechanism, for logs and for `orbit status`, so an
	// operator knows where to look with their own tools.
	Describe() string
}

// ErrHostStateUnsupported means this platform cannot be a gateway.
//
// A refusal rather than a silent no-op. A machine that was told to forward and
// quietly does not is a network where some packets vanish, and the reason is
// three layers away from the symptom.
var ErrHostStateUnsupported = fmt.Errorf(
	"this platform cannot act as a route gateway: forwarding and NAT are " +
		"implemented for Linux only. A Mac can USE routes — nebula installs them — " +
		"but cannot advertise them")

// HostStateFromConfig reads the agent's instructions out of a verified config.
//
// FROM THE VERIFIED BYTES, never from the file on disk. These instructions
// change a machine's firewall and enable forwarding, so they must carry the
// same proof as everything else the control plane sends — reading them from
// nebula.yml would make "who may change this host's netfilter rules" a
// different question from "who may change its configuration", and a weaker one.
func HostStateFromConfig(yamlCfg string) (HostState, error) {
	var doc struct {
		Tun struct {
			Dev string `yaml:"dev"`
		} `yaml:"tun"`
		Orbit *struct {
			Forward    bool     `yaml:"forward"`
			Masquerade []string `yaml:"masquerade"`
		} `yaml:"orbit"`
	}
	if err := yaml.Unmarshal([]byte(yamlCfg), &doc); err != nil {
		return HostState{}, fmt.Errorf("read host state from the configuration: %w", err)
	}
	if doc.Orbit == nil {
		// Not a gateway. The zero value is Empty(), which makes the agent
		// REMOVE anything it left behind rather than skip — a machine whose
		// last route was withdrawn must stop forwarding.
		return HostState{}, nil
	}

	h := HostState{Forward: doc.Orbit.Forward, TunDev: doc.Tun.Dev}
	for _, raw := range doc.Orbit.Masquerade {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return HostState{}, fmt.Errorf("masquerade prefix %q: %w", raw, err)
		}
		h.Masquerade = append(h.Masquerade, p)
	}
	return h, nil
}
