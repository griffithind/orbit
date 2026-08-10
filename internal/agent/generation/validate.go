package generation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Configuration validation, delegated to the nebula binary this host runs.
//
// The agent used to link nebula and call nebula.Main(cfg, configTest=true) in
// process. That was wrong in a way size alone does not capture: the agent
// supervises a STOCK nebula binary whose version it does not choose, while the
// linked-in copy is whatever Orbit was compiled against. The two disagree
// whenever a config option is added, removed, or tightened between releases, so
// the check could pass a configuration the real binary rejects — the exact
// failure validation exists to prevent — or reject one it would have accepted,
// which strands a host on an old generation for no reason.
//
// Shelling out to `nebula -test -config` asks the binary that will actually
// load the file. It also removes nebula's root package, and with it gvisor and
// the prometheus client, from the agent: 18.1 MB to roughly 7 MB on every
// managed host.

// DefaultNebulaBinary is looked up on PATH when no path is configured.
const DefaultNebulaBinary = "nebula"

// validateTimeout bounds the config test. `nebula -test` parses the config,
// loads the PKI, and builds the firewall; it opens no sockets and dials
// nothing, so it is fast or it is stuck.
const validateTimeout = 30 * time.Second

// ErrValidationUnavailable means the config test could not be RUN — no nebula
// binary, not executable, killed by a signal. It is deliberately distinct from
// a validation failure, because the two call for opposite responses: a config
// nebula rejects must not be applied, while an absent validator must not stop a
// host from ever applying anything.
var ErrValidationUnavailable = errors.New("nebula config test could not be run")

// ConfigValidator checks a rendered configuration before it goes live.
type ConfigValidator interface {
	// Validate returns nil if the configuration at path is acceptable, an error
	// describing the rejection if it is not, and an error wrapping
	// ErrValidationUnavailable if it could not tell.
	Validate(ctx context.Context, path string) error
	Describe() string
}

// NebulaBinaryValidator runs `nebula -test -config <path>`.
type NebulaBinaryValidator struct {
	// Binary is the nebula executable: a path, or a name resolved on PATH.
	// Empty means DefaultNebulaBinary.
	Binary string
}

func (v NebulaBinaryValidator) Describe() string {
	if v.Binary == "" {
		return DefaultNebulaBinary + " -test"
	}
	return v.Binary + " -test"
}

func (v NebulaBinaryValidator) Validate(ctx context.Context, path string) error {
	bin := v.Binary
	if bin == "" {
		bin = DefaultNebulaBinary
	}
	// Resolved before running so that "not installed" is reported as
	// unavailable rather than as a rejected configuration.
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrValidationUnavailable, bin, err)
	}

	ctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, resolved, "-test", "-config", path).CombinedOutput()
	if err == nil {
		return nil
	}

	// A non-zero exit is nebula's verdict on the configuration and is the whole
	// point of asking. Anything else — the binary could not be started, the
	// context expired, a signal killed it — is us failing to ask.
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return fmt.Errorf("%w: %s: %v", ErrValidationUnavailable, resolved, err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %s did not finish within %s", ErrValidationUnavailable, resolved, validateTimeout)
	}

	// nebula prints the reason to stderr; carrying it through is the difference
	// between "nebula rejects the configuration" and a message an operator can
	// act on without reproducing anything.
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		detail = exitErr.String()
	}
	return fmt.Errorf("nebula rejects the configuration: %s", detail)
}

// validateFile writes cfg to a temporary file and validates it.
//
// A file rather than stdin because `nebula -test` takes a path, and because the
// paths INSIDE the configuration — the CA bundle, the certificate, the key —
// are absolute and already point at the staged or live copies. Only the config
// itself needs somewhere to live for the length of the check.
//
// The temporary file goes beside the real one rather than in /tmp: the config
// directory is where this host's state already lives, it is the directory
// systemd's StateDirectory grants, and /tmp on a hardened host may be noexec,
// small, or a different filesystem.
func (a *Applier) validateFile(ctx context.Context, cfg string) error {
	v := a.validator()
	if v == nil {
		return nil
	}

	dir := filepath.Dir(a.Layout.ConfigPath())
	f, err := os.CreateTemp(dir, ".orbit-validate-*.yml")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrValidationUnavailable, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if _, err := f.WriteString(cfg); err != nil {
		f.Close()
		return fmt.Errorf("%w: %v", ErrValidationUnavailable, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrValidationUnavailable, err)
	}
	return v.Validate(ctx, tmp)
}
