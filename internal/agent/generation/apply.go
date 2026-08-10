// Package agent applies control-plane state to a managed host.
//
// The agent supervises the stock nebula binary rather than embedding it: the
// operator upgrades nebula on their own schedule, an agent crash cannot take
// down the data plane, and nebula's own signed releases and platform packaging
// are inherited rather than reimplemented.
//
// Everything the agent owns for one network lives in one per-network directory
// (see layout.go). A host on two networks runs two agents over two directories
// and shares nothing between them.
//
// The apply sequence is the part that matters. Configuration is validated in a
// staging directory using nebula's own loader before anything live is touched,
// so the common failure (a config nebula rejects) never reaches the running
// node at all. Only after validation passes are files moved into place, and
// only then is the change delivered — as a hot reload where nebula can take one,
// and as a verified process restart where it cannot. A failure after that point
// restores the previous generation and delivers it the same way.
package generation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/griffithind/orbit/internal/agent/dataplane"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/wire"
)

// ErrRestartRequired means this generation cannot be hot-loaded and this host
// has no way to restart nebula.
//
// A distinct error because the caller must treat it as permanent for this
// generation: the control plane will keep offering it, and retrying every poll
// interval only produces the same refusal forever.
var ErrRestartRequired = errors.New("generation requires a nebula restart")

// ErrRestartFailed means the restart was attempted and did not take: the
// command failed, nebula did not come back, or the process that came back is
// the same one that was running before.
//
// Also distinct, and for the sharper reason: a restart drops every tunnel on
// the host. Retrying one every poll interval is not a slow loop, it is a
// permanent outage delivered a minute at a time.
var ErrRestartFailed = errors.New("nebula restart did not take effect")

// Reloader makes a running nebula pick up new configuration without restarting.
type Reloader interface {
	Reload(ctx context.Context) error
	// Describe is used in logs so an operator can see what the agent will
	// actually do without reading its flags.
	Describe() string
}

// Applier writes control-plane state to disk and delivers it to nebula.
// Restart timings the Applier uses when its own are unset.
const (
	restartSettleDefault = 45 * time.Second
	restartPollDefault   = 500 * time.Millisecond
)

type Applier struct {
	Layout   paths.Layout
	Reloader Reloader

	// Supervisor restarts nebula and reports whether it is running.
	//
	// Needed whenever a generation cannot be hot-loaded, which in practice means
	// the host's overlay address or curve changed: nebula rejects a reload whose
	// certificate networks differ. Nil means such a generation is REFUSED rather
	// than applied in a way that would silently leave the old certificate
	// running until it expires.
	Supervisor dataplane.Supervisor

	// Verifier confirms the host still works after the change is delivered. Nil
	// means no verification, which also means the rollback path is never
	// exercised.
	Verifier Verifier

	// NebulaBinary is the nebula executable used to validate a candidate
	// configuration before it goes live: a path, or a name resolved on PATH.
	// Empty means DefaultNebulaBinary.
	NebulaBinary string

	// Validator overrides how configurations are checked. Nil takes the
	// default, which is the whole point — see validator(). Tests that drive
	// validation supply their own.
	Validator ConfigValidator

	// DisableValidation turns the check off. It exists so that "I do not want
	// it" and "I forgot" cannot look the same in a struct literal.
	DisableValidation bool

	// RestartSettle and RestartPoll bound the wait for a restart to show up as a
	// new process. Zero uses the defaults.
	RestartSettle time.Duration
	RestartPoll   time.Duration

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

	// RequiresRestart is the control plane saying this generation cannot be
	// hot-loaded, for a reason the agent cannot infer from the certificate: a
	// changed tun device, a changed listen port, anything nebula only reads at
	// startup.
	//
	// It can only ESCALATE. The agent's own certificate comparison still runs,
	// and a control plane that says "reload" about a certificate whose networks
	// changed does not get one — nebula would refuse it, and the host would keep
	// running the old certificate until it expired.
	RequiresRestart bool

	// ConfigSig is the control plane's proof that it produced Config and
	// CABundle. Persisted beside the installed files, with Config as it arrived,
	// so a later start can tell whether what is on disk is still what was sent.
	//
	// Nil only on the paths that do not go through the control plane at all —
	// the control plane rendering its own material in-process, where there is no
	// transport and no disk to diverge from.
	ConfigSig *wire.ConfigSignature
}

// Apply installs a generation.
//
// Order of operations, and why:
//
//  1. stage everything in a sibling directory
//  2. validate the staged config with nebula's own loader
//  3. decide how this generation must be delivered, and refuse now if it cannot be
//  4. back up the live generation
//  5. move staged files into place
//  6. deliver: reload, or restart and prove the restart took
//  7. verify
//  8. on any failure after step 5, restore the backup and deliver it the same way
//
// Validating before step 5 is what keeps a rejected config from ever reaching
// the running node. Deciding at step 3 is what keeps a generation this host
// cannot deliver from displacing one it is successfully running. Rollback covers
// what neither can: a config that is structurally valid but that the running
// nebula refuses, a restart that does not come back, or a change that severs
// connectivity.
func (a *Applier) Apply(ctx context.Context, m Material) (err error) {
	if m.Config == "" {
		return errors.New("refusing to apply an empty configuration")
	}
	if err := a.ensureDirs(); err != nil {
		return err
	}

	// Captured BEFORE localize, because this is what was signed. The rewrite
	// below is the agent's own, so the bytes that reach disk as nebula.yml are
	// not the bytes the control plane put its name to — and keeping the original
	// is what makes the installed file checkable later.
	signedConfig := m.Config

	// The control plane renders canonical paths because it cannot know where
	// this host keeps its files. The agent does, so it rewrites them. This is
	// what makes a per-network -dir work rather than silently producing a config
	// that points at files nobody wrote.
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

	if err := stage(paths.CAName, m.CABundle, 0o644); err != nil {
		return err
	}
	if err := stage(paths.CertName, m.Certificate, 0o644); err != nil {
		return err
	}
	if err := stage(paths.KeyName, m.PrivateKey, 0o600); err != nil {
		return err
	}
	if err := stage(a.Layout.ConfigName(), m.Config, 0o644); err != nil {
		return err
	}

	// The signed original and its proof are part of the generation, so they are
	// staged, backed up and rolled back with everything else. A revert that
	// restored the config but left the previous signature behind would leave
	// every later check failing against a generation that is running correctly.
	if m.ConfigSig != nil {
		sigJSON, err := json.Marshal(m.ConfigSig)
		if err != nil {
			return fmt.Errorf("encode config signature: %w", err)
		}
		if err := stage(paths.SignedConfigName, signedConfig, 0o644); err != nil {
			return err
		}
		if err := stage(paths.SigName, string(sigJSON), 0o644); err != nil {
			return err
		}
	}

	// Validate against the staged material, not the live material. The rendered
	// config references absolute production paths, so validation uses a copy
	// with those paths rewritten to the staging directory; otherwise we would be
	// validating the new config against the old certificates.
	if err := a.validateStaged(ctx, staged, m); err != nil {
		return fmt.Errorf("refusing to apply: %w", err)
	}

	// Decide how this generation has to be delivered before installing
	// anything, so a generation that cannot be delivered at all is refused while
	// the previous one is still intact and running.
	mode, err := a.modeFor(m)
	if err != nil {
		return err
	}
	if mode == ModeRestart {
		if a.Supervisor == nil {
			return fmt.Errorf("%w, but no supervisor is configured: this generation changes "+
				"something nebula only reads at startup (overlay address, curve, or a "+
				"control-plane restart flag), which nebula cannot hot-load (pki.go reloadCerts). "+
				"Configure -restart, or restart nebula manually after applying. Refusing to "+
				"install a certificate that would be silently ignored", ErrRestartRequired)
		}
		a.Log.Warn("generation requires a nebula restart, tunnels on this network will drop",
			"network", a.Layout.Network, "supervisor", a.Supervisor.Describe())
	}

	targets := a.Layout.Targets()
	backup, err := a.backup(targets)
	if err != nil {
		return fmt.Errorf("back up current generation: %w", err)
	}

	rollback := func(cause error) error {
		a.Log.Error("apply failed, rolling back", "network", a.Layout.Network, "error", cause)
		if rerr := a.restore(backup, targets); rerr != nil {
			// Both the apply and the rollback failed. Say so explicitly: this
			// host needs a human, and a generic error would bury that.
			return fmt.Errorf("apply failed (%w) AND rollback failed (%v); host may be in an inconsistent state", cause, rerr)
		}
		// Deliver the restored generation the same way it was delivered
		// originally, or the rollback installs files nobody reads. A restart-mode
		// rollback restarts again: the tunnels are already down, and the process
		// that is up — if any — is the one that just failed.
		if rerr := a.deliver(ctx, mode); rerr != nil {
			return fmt.Errorf("apply failed (%w); rolled back but %s failed (%v)", cause, mode, rerr)
		}
		a.Log.Info("rolled back to the previous generation", "network", a.Layout.Network)
		return cause
	}

	// Install in generation() order: certificate material first, configuration
	// last, so a crash mid-install leaves nebula reading an old config that
	// still points at files that exist.
	for _, f := range a.Layout.Generation() {
		src, ok := staged[f.Name]
		if !ok {
			continue // not part of this generation, e.g. an unchanged key
		}
		if err := os.Rename(src, f.Path); err != nil {
			return rollback(fmt.Errorf("install %s: %w", f.Name, err))
		}
	}
	// fsync the directories so the renames survive a crash.
	a.syncDirs()

	if err := a.deliver(ctx, mode); err != nil {
		return rollback(err)
	}

	// Verification is what makes rollback meaningful. Without it "applied" only
	// means the files were written and a signal was sent, which is not the same
	// as the host still being on the mesh.
	//
	// It does not replace the restart proof in deliver(). A host that refused the
	// new certificate is still reachable at its OLD address on its OLD, valid
	// certificate, so this check passes for exactly the failure it looks like it
	// would catch.
	if a.Verifier != nil {
		if err := a.Verifier.Verify(ctx); err != nil {
			return rollback(fmt.Errorf("post-apply verification (%s): %w", a.Verifier.Describe(), err))
		}
	}

	a.Log.Info("applied configuration",
		"network", a.Layout.Network, "config", a.Layout.ConfigPath(),
		"delivery", mode.String(),
		"verify", describeVerifier(a.Verifier))
	return nil
}

// deliver hands the installed generation to the running nebula.
func (a *Applier) deliver(ctx context.Context, mode ApplyMode) error {
	if mode == ModeReload {
		if err := a.Reloader.Reload(ctx); err != nil {
			return fmt.Errorf("reload: %w", err)
		}
		return nil
	}
	return a.restart(ctx)
}

// restart replaces the nebula process and proves it was replaced.
//
// The proof is the whole point. Without it, "restart" means "a command exited
// zero", and every way a restart can fail to take — a unit that is masked, a
// unit that points at another network's directory, a nebula that failed to bind
// and was left in the old process, a service manager that reloaded instead of
// restarting — reports success and leaves the host running the previous
// certificate until it expires.
func (a *Applier) restart(ctx context.Context) error {
	before, err := a.Supervisor.Status(ctx)
	if err != nil {
		// Not fatal on its own: the restart may still work. But it does mean
		// the "did the process change" comparison has nothing to compare against.
		a.Log.Warn("could not read nebula status before restarting",
			"network", a.Layout.Network, "error", err)
	}

	if err := a.Supervisor.Restart(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrRestartFailed, err)
	}

	if !before.Known {
		// Say it every time, and say what is actually lost. A restart that did
		// not happen looks identical to one that did, and the reachability
		// verifier cannot tell them apart because the old certificate still
		// works. This is a degraded configuration, not a neutral one.
		a.Log.Warn("restart delivered but NOT verified: this supervisor cannot observe the "+
			"nebula process, so the agent cannot tell a restart that took effect from one that "+
			"silently did not. Use -restart unit:<systemd unit>, or give -reload a pidfile",
			"network", a.Layout.Network, "supervisor", a.Supervisor.Describe())
		return nil
	}
	return a.confirmRestarted(ctx, before)
}

// confirmRestarted waits for nebula to come back as a different process.
func (a *Applier) confirmRestarted(ctx context.Context, before dataplane.Status) error {
	settle := a.RestartSettle
	if settle <= 0 {
		settle = restartSettleDefault
	}
	poll := a.RestartPoll
	if poll <= 0 {
		poll = restartPollDefault
	}

	ctx, cancel := context.WithTimeout(ctx, settle)
	defer cancel()

	var last dataplane.Status
	for {
		st, err := a.Supervisor.Status(ctx)
		if err == nil {
			last = st
			switch {
			case !st.Known:
				// It was observable a moment ago and is not now. Treat that as
				// unproven rather than as success.
			case st.Running && st.Instance != "" && st.Instance != before.Instance:
				a.Log.Info("nebula restarted", "network", a.Layout.Network, "status", st.Detail)
				return nil
			case st.Running && st.Instance == "" && before.Instance == "":
				// Observable, running, but with no way to distinguish runs. The
				// same degraded case as an unknown supervisor; do not pretend.
				a.Log.Warn("nebula is running but the restart could not be verified",
					"network", a.Layout.Network, "status", st.Detail)
				return nil
			}
		}

		select {
		case <-ctx.Done():
			if last.Known && !last.Running {
				return fmt.Errorf("%w: nebula is not running after the restart (%s)", ErrRestartFailed, last.Detail)
			}
			return fmt.Errorf("%w: nebula did not come back as a new process within %s; "+
				"it is still running the configuration it had before, which means the new "+
				"certificate is installed but not in effect (%s)", ErrRestartFailed, settle, last.Detail)
		case <-time.After(poll):
		}
	}
}

// modeFor decides how this generation must reach nebula.
//
// Two independent sources, and the stricter one wins. The agent compares the
// incoming certificate with the installed one, which catches every case nebula
// itself would refuse. The control plane can escalate on top of that for changes
// no certificate reveals. Neither can de-escalate the other.
func (a *Applier) modeFor(m Material) (ApplyMode, error) {
	mode := ModeReload
	if m.Certificate != "" {
		current, err := os.ReadFile(a.Layout.Paths.Cert)
		switch {
		case err == nil:
			mode, err = ModeFor(string(current), m.Certificate)
			if err != nil {
				return ModeRestart, err
			}
		case os.IsNotExist(err):
			// First enrollment: nothing is running to reload or restart.
		default:
			return ModeReload, fmt.Errorf("read current certificate: %w", err)
		}
	}
	if m.RequiresRestart {
		mode = ModeRestart
	}
	return mode, nil
}

func describeVerifier(v Verifier) string {
	if v == nil {
		return "none"
	}
	return v.Describe()
}

func (a *Applier) ensureDirs() error {
	if err := os.MkdirAll(a.Layout.Dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", a.Layout.Dir, err)
	}
	return nil
}

func (a *Applier) syncDirs() {
	_ = syncDir(a.Layout.Dir)
}

// localize rewrites the paths the control plane rendered into this host's
// actual layout.
//
// It reads pki.ca / pki.cert / pki.key out of the incoming configuration and
// replaces those exact strings, rather than searching for a hard-coded default.
// The difference matters now that the directory is per network: the control
// plane may render /var/lib/orbit/<slug>/… for a slug this agent's -dir does not
// spell the same way, and a rewrite keyed on one fixed default would quietly
// leave the config pointing at files nobody wrote. Substituting the values the
// config actually carries cannot miss.
//
// Textual substitution rather than re-serialising the YAML, because the rendered
// output is deterministic by design and re-emitting it would destroy that.
func (a *Applier) localize(cfg string) string {
	var doc struct {
		PKI struct {
			CA   string `yaml:"ca"`
			Cert string `yaml:"cert"`
			Key  string `yaml:"key"`
		} `yaml:"pki"`
	}
	// The control plane renders a file path for pki.key because it does not
	// know — and must not know — where this host keeps its private key, or
	// whether it has one at all. A host whose key lives on a token substitutes
	// the URI here: the same rewrite, a different destination.
	key := a.Layout.Paths.Key
	replacements := [][2]string{}
	if err := yaml.Unmarshal([]byte(cfg), &doc); err == nil {
		replacements = [][2]string{
			{doc.PKI.CA, a.Layout.Paths.CA},
			{doc.PKI.Cert, a.Layout.Paths.Cert},
			{doc.PKI.Key, key},
		}
	} else {
		// Unparseable: validateStaged will reject it in a moment with a far
		// better message. Fall back to the defaults so the error it reports is
		// about the config rather than about missing files.
		def := nebulacfg.DefaultPaths()
		replacements = [][2]string{
			{def.CA, a.Layout.Paths.CA},
			{def.Cert, a.Layout.Paths.Cert},
			{def.Key, key},
		}
	}
	for _, r := range replacements {
		if r[0] != "" && r[0] != r[1] {
			cfg = strings.ReplaceAll(cfg, r[0], r[1])
		}
	}
	return cfg
}

// validateStaged runs the candidate configuration through nebula's own config
// test, which loads the PKI and builds the firewall exactly as a running node
// would.
//
// This is the agent's strongest guard. It catches a malformed config, a
// certificate that does not match its CA, an expired certificate, and an
// unparseable firewall rule, all before the live configuration is touched.
//
// A generation does not always carry every file. A blocklist push carries only
// a configuration; a renewal that reuses the key carries no key. For each file,
// validation must therefore point at the staged copy when this generation
// brings one and at the live copy otherwise — pointing at a staged path that
// was never written makes every config-only push fail validation, which is
// exactly the shape of bug that only shows up once push is wired end to end.
func (a *Applier) validateStaged(ctx context.Context, staged map[string]string, m Material) error {
	cfg := m.Config
	for _, f := range []struct{ live, name string }{
		{a.Layout.Paths.CA, paths.CAName},
		{a.Layout.Paths.Cert, paths.CertName},
		{a.Layout.Paths.Key, paths.KeyName},
	} {
		if p, ok := staged[f.name]; ok {
			cfg = strings.ReplaceAll(cfg, f.live, p)
		}
		// Not staged: leave the live path. The existing file is what nebula
		// will keep using, so it is what must be validated against.
	}

	err := a.validateFile(ctx, cfg)
	switch {
	case err == nil:
		return nil

	case errors.Is(err, ErrValidationUnavailable):
		// Could not ASK, which is not the same as being told no, and must not
		// be treated as one. A host where nebula lives somewhere unexpected, or
		// where it is not installed yet at first enrollment, would otherwise be
		// unable to apply anything at all — the agent would refuse every
		// generation forever and the host would silently never converge.
		//
		// Proceeding is safe enough because this is not the only guard: a
		// generation that breaks the host is reverted and quarantined by the
		// apply loop after verification fails. Validation makes that rarer and
		// cheaper; it is not what makes it survivable.
		a.Log.Warn("could not validate the configuration; applying without it",
			"error", err, "validator", a.validatorName(),
			"consequence", "a bad generation will be caught by verification and reverted, not refused up front")
		return nil

	default:
		return err
	}
}

// validator resolves the check to run.
//
// Nil takes the DEFAULT rather than meaning "off", because Applier is built
// from a struct literal at every call site and a field omitted from a literal
// is silent. If nil meant off, the one call site that forgot it would lose the
// agent's strongest guard with nothing to show for it — no error, no log line,
// no failing test, since every test harness would have forgotten it too.
// DisableValidation is how a caller says so out loud.
func (a *Applier) validator() ConfigValidator {
	switch {
	case a.DisableValidation:
		return nil
	case a.Validator != nil:
		return a.Validator
	default:
		return NebulaBinaryValidator{Binary: a.NebulaBinary}
	}
}

func (a *Applier) validatorName() string {
	v := a.validator()
	if v == nil {
		return "disabled"
	}
	return v.Describe()
}

// PreviousDir is where the last known-good generation lives.
func (a *Applier) PreviousDir() string { return a.Layout.PreviousDir() }

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

// Revert restores the previous generation and delivers it.
//
// Used by the unreachable-guard: a configuration can be structurally valid,
// install cleanly, and still sever this host's path back to the control plane
// (a firewall rule that drops the agent port, a lighthouse list that no longer
// resolves). Nothing local can detect that at apply time, so the only defence
// is noticing sustained loss of contact afterwards and undoing the change.
//
// The delivery decision is made here too, and for the same reason it is made in
// Apply: going BACK across an address change is as un-hot-loadable as going
// forward. A revert that only sent SIGHUP would be refused by nebula exactly as
// the original apply would have been, leaving a host that has restored the old
// certificate on disk, reported itself as reverted, and is still running the
// generation that broke it.
//
// Returns an error if there is no previous generation to return to, which is
// the first-enrollment case: there is nothing better to fall back to, and
// silently doing nothing would look like a successful revert.
func (a *Applier) Revert(ctx context.Context) error {
	dir := a.PreviousDir()
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("no previous generation to revert to: %w", err)
	}

	targets := a.Layout.Targets()
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

	mode, err := a.revertMode(backup)
	if err != nil {
		return err
	}
	if mode == ModeRestart && a.Supervisor == nil {
		return fmt.Errorf("%w: reverting crosses an overlay address or curve change, which "+
			"nebula cannot hot-load. Configure -restart, or restart nebula by hand after "+
			"reverting. Refusing to restore a certificate that would be silently ignored",
			ErrRestartRequired)
	}

	if err := a.restore(backup, targets); err != nil {
		return fmt.Errorf("restore previous generation: %w", err)
	}
	a.syncDirs()

	if err := a.deliver(ctx, mode); err != nil {
		return fmt.Errorf("reverted on disk but %s failed: %w", mode, err)
	}

	a.Log.Warn("reverted to the previous generation",
		"network", a.Layout.Network, "from", dir, "delivery", mode.String())
	return nil
}

// revertMode compares the certificate about to be restored with the one running.
func (a *Applier) revertMode(backup map[string]string) (ApplyMode, error) {
	prev, ok := backup[paths.CertName]
	if !ok {
		return ModeReload, nil
	}
	prevPEM, err := os.ReadFile(prev)
	if err != nil {
		return ModeReload, fmt.Errorf("read previous certificate: %w", err)
	}
	current, err := os.ReadFile(a.Layout.Paths.Cert)
	if err != nil {
		if os.IsNotExist(err) {
			return ModeReload, nil
		}
		return ModeReload, fmt.Errorf("read current certificate: %w", err)
	}
	return ModeFor(string(current), string(prevPEM))
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

// MaterialFromEnroll converts an enrollment response into a generation.
func MaterialFromEnroll(resp *wire.EnrollResponse, privateKeyPEM string) Material {
	return Material{
		Config:      resp.Config,
		CABundle:    resp.CABundle,
		Certificate: resp.Certificate,
		PrivateKey:  privateKeyPEM,
		ConfigSig:   resp.ConfigSig,
	}
}
