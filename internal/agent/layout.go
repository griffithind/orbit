package agent

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/griffithind/orbit/internal/nebulacfg"
)

// A managed host runs ONE nebula process and ONE agent process PER NETWORK.
//
// Nothing below assumes it is the only Orbit on the box. A host joined to two
// networks has two of everything: two directories, two nebula processes, two
// tun devices, two listen ports, two agent processes, and — because a network
// is owned by whoever runs its control plane — possibly two different control
// planes that never learn of each other. Every path the agent touches is
// therefore derived from Layout.Dir, which is per network; there is no
// process-wide state, no fixed pidfile, no fixed unit name, and no shared
// scratch space anywhere in this package.
//
// One agent process per network rather than one agent driving several: the
// agent's whole job is to hold a credential for one identity and talk to the
// control plane that issued it. A multi-network agent would hold several
// unrelated credentials in one address space, fail over between endpoints
// belonging to different trust domains, and turn "the agent for network B
// crashed" into "the agent for network A stopped renewing". The per-network
// process is also what makes systemd's template units, and therefore per-network
// restart, status, and log isolation, work at all.
//
// What the agent cannot arbitrate is the pair of settings that are global to
// the host but rendered per network: listen.port and tun.dev. Two networks that
// both render port 4242 collide, and neither control plane can see the other.
// checkInstanceCollisions below reports that rather than leaving it as an
// intermittent bind failure at nebula start.

// DefaultRoot is the parent of every per-network directory on a managed host.
//
// Under /var/lib because everything beneath it is runtime state the agent
// writes and replaces. On an image-based system (bootc, OSTree, Fedora CoreOS)
// /usr is read-only and /etc is an overlay the image reconciles on upgrade, so
// state written to /etc can be reverted underneath a running host.
const DefaultRoot = "/var/lib/orbit"

// DirFor is the directory a network's agent owns, and the value systemd's
// StateDirectory=orbit/<slug> creates.
func DirFor(network string) string { return filepath.Join(DefaultRoot, network) }

// DeviceKeyName is the machine's own identity key, and it deliberately sits at
// the ROOT rather than inside a per-network directory.
//
// That placement is the model: a device is one machine across every network it
// joins and every control plane it talks to (docs/model.md §1). A copy per
// network would make a laptop on three meshes three devices, which is exactly
// the conflation the device noun exists to remove — and posture reported three
// times with three chances to disagree is what it would cost.
//
// It also means removing one network's directory does not destroy the machine's
// identity, which matters because that identity is what lets a host with no
// working tunnel still reach a control plane.
const DeviceKeyName = "device.key"

// DeviceKeyPath is where the machine's identity key lives under root.
func DeviceKeyPath(root string) string {
	if root == "" {
		root = DefaultRoot
	}
	return filepath.Join(root, DeviceKeyName)
}

// ValidateNetwork checks a network slug is safe as a path component and as a
// systemd instance name.
//
// The charset is deliberately narrower than either would strictly require. A
// slug becomes a directory name under DefaultRoot and an instance name after
// systemd's %i unescaping, and the failure modes on those two paths are not the
// same: "." and ".." escape the root, "/" escapes it further, and systemd
// escaping turns "-" into a path separator in unit names. Refusing everything
// but [a-z0-9-] means neither mechanism can be surprised.
func ValidateNetwork(slug string) error {
	if slug == "" {
		return fmt.Errorf("network slug is empty")
	}
	if len(slug) > 32 {
		return fmt.Errorf("network slug %q is longer than 32 characters", slug)
	}
	for _, r := range slug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return fmt.Errorf("network slug %q contains %q; only lowercase letters, digits and hyphens are allowed", slug, string(r))
	}
	return nil
}

// ConfigMode is how Orbit's configuration reaches nebula.
type ConfigMode int

const (
	// ConfigAuthoritative points nebula at ONE file that Orbit owns completely.
	//
	// This is the default, and it is the only mode in which Orbit can be said to
	// control the host's configuration. Nebula merges every .yml in a config
	// DIRECTORY with mergo.WithAppendSlice, so list values — firewall rules
	// above all — are CONCATENATED across files. An operator rule and an Orbit
	// rule then both apply, and there is no way for Orbit to see or remove the
	// operator's. Pointing nebula at a single file removes the merge entirely:
	// config.C.resolve (config/config.go) stats the path, and a non-directory is
	// loaded as exactly that file.
	ConfigAuthoritative ConfigMode = iota

	// ConfigFragment writes config.d/50-orbit.yml alongside operator files and
	// lets nebula merge.
	//
	// The escape hatch for a host that genuinely needs operator configuration
	// next to Orbit's. It costs the property above: anything that must be
	// guaranteed absent has to be absent from every file, which Orbit cannot
	// enforce.
	ConfigFragment
)

func (m ConfigMode) String() string {
	if m == ConfigFragment {
		return "fragment"
	}
	return "authoritative"
}

// ParseConfigMode reads the -mode flag.
func ParseConfigMode(s string) (ConfigMode, error) {
	switch s {
	case "", "authoritative":
		return ConfigAuthoritative, nil
	case "fragment":
		return ConfigFragment, nil
	default:
		return ConfigAuthoritative, fmt.Errorf("unknown config mode %q (want \"authoritative\" or \"fragment\")", s)
	}
}

// The names inside a per-network directory. These are a contract with the
// control plane's renderer and with the systemd units in deploy/: changing one
// of them means changing all three.
const (
	// ConfigFileName is the complete configuration in authoritative mode. It is
	// what `nebula -config` points at — the FILE, not a directory.
	ConfigFileName = "nebula.yml"

	// FragmentName is the single file Orbit owns in fragment mode.
	//
	// The numeric prefix places it after a conventional 00-base.yml so Orbit's
	// scalar settings win; list values are appended by nebula regardless of
	// order, which is the property fragment mode gives up on.
	FragmentName = "50-orbit.yml"

	// ConfigDirName is the merge directory nebula is pointed at in fragment mode.
	ConfigDirName = "config.d"

	CAName   = "ca.crt"
	CertName = "host.crt"
	KeyName  = "host.key"

	// StateFileName holds the agent's own state: control plane URL, epochs,
	// guard state. Not part of a generation and never backed up — it describes
	// the agent, not the configuration.
	StateFileName = "agent.json"

	// PreviousDirName holds the last known-good generation.
	//
	// A stable directory, not a fresh temp one per apply. The temp-per-apply
	// version leaked: nothing removed them, so the directory accumulated a
	// backup directory for every configuration change the host ever received.
	// It also meant there was no single place to revert *to* later, which the
	// unreachable-guard needs.
	PreviousDirName = ".previous"
)

// Layout describes where things live for ONE network on a managed host.
type Layout struct {
	// Network is the network's slug, used for logs and to name the systemd
	// instance. Empty is tolerated: it is a label, not the source of any path.
	Network string

	// Dir is the per-network directory the agent owns, e.g.
	// /var/lib/orbit/prod. Every other path in this struct is derived from it,
	// which is what keeps two networks on one host from sharing anything.
	Dir string

	Mode ConfigMode

	// Paths are the certificate and key locations referenced by the rendered
	// configuration. The agent rewrites the config to match these on receipt
	// (see Applier.localize), so a control plane rendering one layout and an
	// agent running another is not a mismatch.
	Paths nebulacfg.Paths
}

// DefaultLayout is the per-network layout in authoritative mode.
func DefaultLayout(dir string) Layout { return LayoutFor(dir, ConfigAuthoritative) }

// FragmentLayout is the per-network layout in fragment mode.
func FragmentLayout(dir string) Layout { return LayoutFor(dir, ConfigFragment) }

func LayoutFor(dir string, mode ConfigMode) Layout {
	return Layout{
		// A slug is not required to derive any path, so taking it from the
		// directory name keeps -dir the single source of truth while still
		// giving logs something an operator recognises.
		Network: filepath.Base(dir),
		Dir:     dir,
		Mode:    mode,
		Paths: nebulacfg.Paths{
			CA:   filepath.Join(dir, CAName),
			Cert: filepath.Join(dir, CertName),
			Key:  filepath.Join(dir, KeyName),
		},
	}
}

// ConfigDir is the merge directory, or "" in authoritative mode where there
// is none.
func (l Layout) ConfigDir() string {
	if l.Mode == ConfigFragment {
		return filepath.Join(l.Dir, ConfigDirName)
	}
	return ""
}

// ConfigName is the basename of the file Orbit owns.
func (l Layout) ConfigName() string {
	if l.Mode == ConfigFragment {
		return FragmentName
	}
	return ConfigFileName
}

// ConfigPath is the file Orbit writes.
func (l Layout) ConfigPath() string {
	if l.Mode == ConfigFragment {
		return filepath.Join(l.Dir, ConfigDirName, FragmentName)
	}
	return filepath.Join(l.Dir, ConfigFileName)
}

// NebulaConfigArg is what `nebula -config` must be given.
//
// A FILE in authoritative mode and a DIRECTORY in fragment mode, and the
// difference is the whole point of the modes: nebula merges a directory and
// loads a file verbatim.
func (l Layout) NebulaConfigArg() string {
	if l.Mode == ConfigFragment {
		return filepath.Join(l.Dir, ConfigDirName)
	}
	return filepath.Join(l.Dir, ConfigFileName)
}

// PreviousDir is where the last known-good generation lives.
func (l Layout) PreviousDir() string { return filepath.Join(l.Dir, PreviousDirName) }

// StatePath is the agent's state file.
func (l Layout) StatePath() string { return filepath.Join(l.Dir, StateFileName) }

// generation names the files that make up one generation, in the order they are
// installed. The config goes last so a crash mid-install leaves nebula reading
// the old config against the old certificate rather than a new config against
// files that are not there yet.
func (l Layout) generation() []struct{ Name, Path string } {
	return []struct{ Name, Path string }{
		{CAName, l.Paths.CA},
		{CertName, l.Paths.Cert},
		{KeyName, l.Paths.Key},
		{l.ConfigName(), l.ConfigPath()},
	}
}

func (l Layout) targets() map[string]string {
	out := map[string]string{}
	for _, f := range l.generation() {
		out[f.Name] = f.Path
	}
	return out
}

// Describe is what the agent logs at startup so an operator can see the layout
// without reading flags.
func (l Layout) Describe() string {
	return fmt.Sprintf("%s mode, nebula -config %s", l.Mode, l.NebulaConfigArg())
}

// SlugFromUnitInstance recovers a network slug from a systemd instance name.
//
// Present so an operator can pass %i straight through. systemd escapes "/" as
// "-" in instance names, but a valid slug contains neither a "/" nor anything
// else systemd would have escaped, so the only transformation needed is the
// validation itself.
func SlugFromUnitInstance(instance string) (string, error) {
	s := strings.TrimSpace(instance)
	if err := ValidateNetwork(s); err != nil {
		return "", err
	}
	return s, nil
}
