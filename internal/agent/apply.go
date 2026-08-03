// Package agent applies control-plane state to a managed host.
//
// The agent supervises the stock nebula binary rather than embedding it: the
// operator upgrades nebula on their own schedule, an agent crash cannot take
// down the data plane, and nebula's own signed releases and platform packaging
// are inherited rather than reimplemented.
//
// The apply sequence is the part that matters. Configuration is validated in a
// staging directory using nebula's own loader before anything live is touched,
// so the common failure (a config nebula rejects) never reaches the running
// node at all. Only after validation passes are files moved into place, and
// only then is a reload signalled. A failure after that point restores the
// previous generation and reloads again.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"

	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/wire"
)

// FragmentName is the single file Orbit owns.
//
// The numeric prefix places it after a conventional 00-base.yml so Orbit's
// scalar settings win, while list values (firewall rules) are appended by
// nebula regardless of order.
const FragmentName = "50-orbit.yml"

// Layout describes where things live on the managed host.
type Layout struct {
	// Dir is nebula's configuration directory, e.g. /etc/nebula.
	Dir string
	// ConfigD is the merge directory nebula is pointed at, e.g.
	// /etc/nebula/config.d.
	ConfigD string
	// Paths are the certificate and key locations referenced by the rendered
	// fragment. They must match what the control plane rendered.
	Paths nebulacfg.Paths
}

func DefaultLayout(dir string) Layout {
	return Layout{
		Dir:     dir,
		ConfigD: filepath.Join(dir, "config.d"),
		Paths: nebulacfg.Paths{
			CA:   filepath.Join(dir, "orbit-ca.crt"),
			Cert: filepath.Join(dir, "orbit-host.crt"),
			Key:  filepath.Join(dir, "orbit-host.key"),
		},
	}
}

// Reloader makes a running nebula pick up new configuration.
type Reloader interface {
	Reload(ctx context.Context) error
	// Describe is used in logs so an operator can see what the agent will
	// actually do without reading its flags.
	Describe() string
}

// Applier writes control-plane state to disk and reloads nebula.
type Applier struct {
	Layout   Layout
	Reloader Reloader

	// Restarter is used when a generation cannot be hot-loaded, which in
	// practice means the host's overlay address changed: nebula rejects a
	// reload whose certificate networks differ. Nil means such a generation is
	// refused rather than applied in a way that would silently leave the old
	// certificate running until it expires.
	Restarter Reloader

	// Verifier confirms the host still works after the reload. Nil means no
	// verification, which also means the rollback path is never exercised.
	Verifier Verifier

	Log *slog.Logger
}

// Material is one generation of host state.
type Material struct {
	Config      string
	CABundle    string
	Certificate string
	// PrivateKey is written only at enrollment. On renewal the agent may
	// generate a new key, in which case this is set again; otherwise it is
	// empty and the existing key file is left alone.
	PrivateKey string
}

// Apply installs a generation.
//
// Order of operations, and why:
//
//  1. stage everything in a sibling directory
//  2. validate the staged config with nebula's own loader
//  3. back up the live generation
//  4. move staged files into place
//  5. reload
//  6. on any failure after step 4, restore the backup and reload again
//
// Validating before step 4 is what keeps a rejected config from ever reaching
// the running node. Rollback covers what validation cannot: a config that is
// structurally valid but that the running nebula refuses, or a reload that
// fails for an unrelated reason.
func (a *Applier) Apply(ctx context.Context, m Material) (err error) {
	if m.Config == "" {
		return errors.New("refusing to apply an empty configuration")
	}
	if err := os.MkdirAll(a.Layout.ConfigD, 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	// The control plane renders canonical paths because it cannot know where
	// this host keeps its files. The agent does, so it rewrites them. This is
	// what makes a non-standard -dir work rather than silently producing a
	// config that points at files nobody wrote.
	m.Config = a.localize(m.Config)

	staging, err := os.MkdirTemp(a.Layout.Dir, ".orbit-staging-")
	if err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	// Stage. Key material keeps 0600 even in staging; a window where the key is
	// world-readable is still a window.
	staged := map[string]string{}
	stage := func(name, content string, mode os.FileMode) error {
		if content == "" {
			return nil
		}
		p := filepath.Join(staging, name)
		if err := writeFileSync(p, []byte(content), mode); err != nil {
			return err
		}
		staged[name] = p
		return nil
	}

	if err := stage("ca.crt", m.CABundle, 0o644); err != nil {
		return err
	}
	if err := stage("host.crt", m.Certificate, 0o644); err != nil {
		return err
	}
	if err := stage("host.key", m.PrivateKey, 0o600); err != nil {
		return err
	}
	if err := stage(FragmentName, m.Config, 0o644); err != nil {
		return err
	}

	// Validate against the staged material, not the live material. The rendered
	// config references absolute production paths, so validation uses a copy
	// with those paths rewritten to the staging directory; otherwise we would be
	// validating the new config against the old certificates.
	if err := a.validateStaged(staging, staged, m); err != nil {
		return fmt.Errorf("refusing to apply: %w", err)
	}

	// Decide how this generation has to be delivered before installing
	// anything, so a generation that cannot be applied at all is refused while
	// the previous one is still intact.
	mode, err := a.modeFor(m)
	if err != nil {
		return err
	}
	deliver := a.Reloader
	if mode == ModeRestart {
		if a.Restarter == nil {
			return fmt.Errorf(
				"this generation changes the host's overlay address or curve, which nebula " +
					"cannot hot-load (pki.go reloadCerts); a process restart is required but no " +
					"restarter is configured. Configure one, or restart nebula manually after " +
					"applying. Refusing to install a certificate that would be silently ignored")
		}
		deliver = a.Restarter
		a.Log.Warn("generation requires a restart, tunnels will drop",
			"reason", "certificate networks or curve changed")
	}

	targets := map[string]string{
		"ca.crt":     a.Layout.Paths.CA,
		"host.crt":   a.Layout.Paths.Cert,
		"host.key":   a.Layout.Paths.Key,
		FragmentName: filepath.Join(a.Layout.ConfigD, FragmentName),
	}

	backup, err := a.backup(targets)
	if err != nil {
		return fmt.Errorf("back up current generation: %w", err)
	}

	rollback := func(cause error) error {
		a.Log.Error("apply failed, rolling back", "error", cause)
		if rerr := a.restore(backup, targets); rerr != nil {
			// Both the apply and the rollback failed. Say so explicitly: this
			// host needs a human, and a generic error would bury that.
			return fmt.Errorf("apply failed (%w) AND rollback failed (%v); host may be in an inconsistent state", cause, rerr)
		}
		// Deliver the restored generation the same way it was delivered
		// originally, or the rollback installs files nobody reads.
		if rerr := deliver.Reload(ctx); rerr != nil {
			return fmt.Errorf("apply failed (%w); rolled back but %s failed (%v)", cause, mode, rerr)
		}
		a.Log.Info("rolled back to the previous generation")
		return cause
	}

	for name, dst := range targets {
		src, ok := staged[name]
		if !ok {
			continue // not part of this generation, e.g. an unchanged key
		}
		if err := os.Rename(src, dst); err != nil {
			return rollback(fmt.Errorf("install %s: %w", name, err))
		}
	}
	// fsync the directories so the renames survive a crash.
	_ = syncDir(a.Layout.Dir)
	_ = syncDir(a.Layout.ConfigD)

	if err := deliver.Reload(ctx); err != nil {
		return rollback(fmt.Errorf("%s: %w", mode, err))
	}

	// Verification is what makes rollback meaningful. Without it "applied" only
	// means the files were written and a signal was sent, which is not the same
	// as the host still being on the mesh.
	if a.Verifier != nil {
		if err := a.Verifier.Verify(ctx); err != nil {
			return rollback(fmt.Errorf("post-apply verification (%s): %w", a.Verifier.Describe(), err))
		}
	}

	a.Log.Info("applied configuration",
		"configD", a.Layout.ConfigD, "mode", mode.String(),
		"deliver", deliver.Describe(), "verify", describeVerifier(a.Verifier))
	return nil
}

// modeFor compares the incoming certificate with the one currently installed.
func (a *Applier) modeFor(m Material) (ApplyMode, error) {
	if m.Certificate == "" {
		return ModeReload, nil
	}
	current, err := os.ReadFile(a.Layout.Paths.Cert)
	if err != nil {
		if os.IsNotExist(err) {
			return ModeReload, nil // first enrollment
		}
		return ModeReload, fmt.Errorf("read current certificate: %w", err)
	}
	return ModeFor(string(current), m.Certificate)
}

func describeVerifier(v Verifier) string {
	if v == nil {
		return "none"
	}
	return v.Describe()
}

// localize rewrites the canonical paths the control plane rendered into this
// host's actual layout. A no-op for a host using the default locations.
func (a *Applier) localize(cfg string) string {
	def := nebulacfg.DefaultPaths()
	for _, r := range [][2]string{
		{def.CA, a.Layout.Paths.CA},
		{def.Cert, a.Layout.Paths.Cert},
		{def.Key, a.Layout.Paths.Key},
	} {
		if r[0] != r[1] {
			cfg = strings.ReplaceAll(cfg, r[0], r[1])
		}
	}
	return cfg
}

// validateStaged runs the candidate configuration through nebula's own
// config-test path, which loads the PKI and builds the firewall exactly as a
// running node would.
//
// This is the agent's strongest guard. It catches a malformed fragment, a
// certificate that does not match its CA, an expired certificate, and an
// unparseable firewall rule, all before the live configuration is touched.
//
// A generation does not always carry every file. A blocklist push carries only
// a configuration; a renewal that reuses the key carries no key. For each file,
// validation must therefore point at the staged copy when this generation
// brings one and at the live copy otherwise — pointing at a staged path that
// was never written makes every config-only push fail validation, which is
// exactly the shape of bug that only shows up once push is wired end to end.
func (a *Applier) validateStaged(staging string, staged map[string]string, m Material) error {
	cfg := m.Config
	for _, f := range []struct {
		live string
		name string
	}{
		{a.Layout.Paths.CA, "ca.crt"},
		{a.Layout.Paths.Cert, "host.crt"},
		{a.Layout.Paths.Key, "host.key"},
	} {
		if p, ok := staged[f.name]; ok {
			cfg = strings.ReplaceAll(cfg, f.live, p)
		}
		// Not staged: leave the live path. The existing file is what nebula
		// will keep using, so it is what must be validated against.
	}

	c := config.NewC(discardLogger())
	if err := c.LoadString(cfg); err != nil {
		return fmt.Errorf("nebula cannot parse the configuration: %w", err)
	}
	if _, err := nebula.Main(c, true, "orbit-agent", discardLogger(), nil); err != nil {
		return fmt.Errorf("nebula rejects the configuration: %w", err)
	}
	return nil
}

// PreviousDirName holds the last known-good generation.
//
// A stable directory, not a fresh temp one per apply. The temp-per-apply
// version leaked: nothing removed them, so /etc/nebula accumulated a
// .orbit-backup-* directory for every configuration change the host ever
// received. It also meant there was no single place to revert *to* later,
// which the unreachable-guard needs.
const PreviousDirName = ".orbit-previous"

// PreviousDir is where the last known-good generation lives.
func (a *Applier) PreviousDir() string {
	return filepath.Join(a.Layout.Dir, PreviousDirName)
}

// backup copies the current generation into the previous-generation directory,
// returning the mapping of logical name to backup path. A target that does not
// exist yet (first enrollment) is simply absent from the map.
func (a *Applier) backup(targets map[string]string) (map[string]string, error) {
	dir := a.PreviousDir()
	// Replace wholesale. A partial previous generation, half from this apply
	// and half from the one before, is worse than none: reverting to it would
	// pair a certificate with a configuration that never ran together.
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	out := map[string]string{}
	for name, live := range targets {
		b, err := os.ReadFile(live)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		info, err := os.Stat(live)
		if err != nil {
			return nil, err
		}
		p := filepath.Join(dir, name)
		if err := writeFileSync(p, b, info.Mode().Perm()); err != nil {
			return nil, err
		}
		out[name] = p
	}
	return out, nil
}

// restore puts a backup generation back. A target that had no backup is removed,
// because it did not exist before this apply and leaving it would be a partial
// generation rather than the previous one.
func (a *Applier) restore(backup, targets map[string]string) error {
	var errs []error
	for name, live := range targets {
		b, ok := backup[name]
		if !ok {
			if err := os.Remove(live); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
			continue
		}
		content, err := os.ReadFile(b)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		info, err := os.Stat(b)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := writeFileSync(live, content, info.Mode().Perm()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Revert restores the previous generation and reloads.
//
// Used by the unreachable-guard: a configuration can be structurally valid,
// install cleanly, and still sever this host's path back to the control plane
// (a firewall rule that drops the agent port, a lighthouse list that no longer
// resolves). Nothing local can detect that at apply time, so the only defence
// is noticing sustained loss of contact afterwards and undoing the change.
//
// Returns an error if there is no previous generation to return to, which is
// the first-enrollment case: there is nothing better to fall back to, and
// silently doing nothing would look like a successful revert.
func (a *Applier) Revert(ctx context.Context) error {
	dir := a.PreviousDir()
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("no previous generation to revert to: %w", err)
	}

	targets := map[string]string{
		"ca.crt":     a.Layout.Paths.CA,
		"host.crt":   a.Layout.Paths.Cert,
		"host.key":   a.Layout.Paths.Key,
		FragmentName: filepath.Join(a.Layout.ConfigD, FragmentName),
	}

	backup := map[string]string{}
	for name := range targets {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			backup[name] = p
		}
	}
	if len(backup) == 0 {
		return fmt.Errorf("previous generation at %s is empty", dir)
	}

	if err := a.restore(backup, targets); err != nil {
		return fmt.Errorf("restore previous generation: %w", err)
	}
	_ = syncDir(a.Layout.Dir)
	_ = syncDir(a.Layout.ConfigD)

	if err := a.Reloader.Reload(ctx); err != nil {
		return fmt.Errorf("reverted on disk but reload failed: %w", err)
	}

	a.Log.Warn("reverted to the previous generation", "from", dir)
	return nil
}

// writeFileSync writes and fsyncs a file. The fsync matters: a rename is only
// atomic with respect to a file whose contents have actually reached disk, and
// a crash between write and rename would otherwise install a truncated config.
func writeFileSync(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// OpenFile honours the mode only on creation; an existing file keeps its
	// own, so set it explicitly.
	return os.Chmod(path, mode)
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// MaterialFromEnroll converts an enrollment response into a generation.
func MaterialFromEnroll(resp *wire.EnrollResponse, privateKeyPEM string) Material {
	return Material{
		Config:      resp.Config,
		CABundle:    resp.CABundle,
		Certificate: resp.Certificate,
		PrivateKey:  privateKeyPEM,
	}
}
