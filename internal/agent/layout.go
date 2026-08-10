package agent

import (
	"fmt"
	"path/filepath"

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

// The names inside a per-network directory. These are a contract with the
// control plane's renderer and with the systemd units in deploy/: changing one
// of them means changing all three.
const (
	// ConfigFileName is the complete configuration in authoritative mode. It is
	// what `nebula -config` points at — the FILE, not a directory.
	ConfigFileName = "nebula.yml"

	CAName   = "ca.crt"
	CertName = "host.crt"
	KeyName  = "host.key"

	// SignedConfigName is the config EXACTLY as the control plane sent it, and
	// SigName is the envelope and signature over it.
	//
	// Two extra files rather than a signature over the installed config,
	// because the agent rewrites what it installs: localize substitutes
	// pki.ca, pki.cert and pki.key, since the control plane renders canonical
	// paths and cannot know where this host keeps its files — or whether its
	// key is a file at all. The bytes on disk are therefore not the bytes that
	// were signed.
	//
	// Keeping the original makes the installed file a deterministic function of
	// it: verify the signature over the original, re-run localize, and compare.
	// That is what turns an operator's edit from invisible into detected.
	SignedConfigName = "nebula.signed.yml"
	SigName          = "nebula.sig.json"

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

	// Paths are the certificate and key locations referenced by the rendered
	// configuration. The agent rewrites the config to match these on receipt
	// (see Applier.localize), so a control plane rendering one layout and an
	// agent running another is not a mismatch.
	Paths nebulacfg.Paths
}

// DefaultLayout is the per-network layout.
//
// One layout, since fragment mode was removed: Orbit owns the whole
// configuration or it owns nothing, and the middle case — nebula merging
// Orbit's file with operator-authored ones — is exactly the case where Orbit
// cannot say what a host is running.
func DefaultLayout(dir string) Layout {
	return Layout{
		// A slug is not required to derive any path, so taking it from the
		// directory name keeps -dir the single source of truth while still
		// giving logs something an operator recognises.
		Network: filepath.Base(dir),
		Dir:     dir,
		Paths: nebulacfg.Paths{
			CA:   filepath.Join(dir, CAName),
			Cert: filepath.Join(dir, CertName),
			Key:  filepath.Join(dir, KeyName),
		},
	}
}

// ConfigName is the basename of the file Orbit owns.
func (l Layout) ConfigName() string { return ConfigFileName }

// ConfigPath is the file Orbit writes.
//
// A RECORD, not the thing nebula reads. The agent hands nebula the verified
// bytes in memory (Applier.VerifiedConfig), so this file exists to be read by
// people and to be compared against the signed original — editing it changes
// nothing about what is running.
func (l Layout) ConfigPath() string { return filepath.Join(l.Dir, ConfigFileName) }

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
		{SignedConfigName, l.SignedConfigPath()},
		{SigName, l.SigPath()},
	}
}

// SignedConfigPath is the untouched config the control plane signed.
//
// Beside the state file rather than beside the installed config, because in
// fragment mode the installed config lives in config.d/ next to an operator's
// own files, and a directory nebula merges is the wrong place to put something
// nebula must not read.
func (l Layout) SignedConfigPath() string { return filepath.Join(l.Dir, SignedConfigName) }

// SigPath is the envelope and signature over SignedConfigPath.
func (l Layout) SigPath() string { return filepath.Join(l.Dir, SigName) }

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
	return fmt.Sprintf("network %s in %s", l.Network, l.Dir)
}
