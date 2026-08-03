package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// NoopReloader does nothing. Used when something else owns the nebula process
// lifecycle, such as a test harness or an operator who reloads by hand.
type NoopReloader struct{}

func (NoopReloader) Reload(context.Context) error { return nil }
func (NoopReloader) Describe() string             { return "none" }

// SignalReloader sends SIGHUP to the pid in a pidfile.
//
// SIGHUP is nebula's reload mechanism (config.C CatchHUP) and is hot: tunnels
// survive it. This is the right reloader whenever the pid is knowable, because
// it is the only one that cannot restart the process by accident.
type SignalReloader struct {
	PidFile string
}

func (r SignalReloader) Reload(context.Context) error {
	b, err := os.ReadFile(r.PidFile)
	if err != nil {
		return fmt.Errorf("read pidfile: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("parse pidfile %q: %w", r.PidFile, err)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := p.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal %d: %w", pid, err)
	}
	return nil
}

func (r SignalReloader) Describe() string { return "SIGHUP via " + r.PidFile }

// CommandReloader runs an external command, typically a service manager.
//
// Prefer a reload verb over a restart. A restart drops every tunnel, and for a
// certificate rotation that is both unnecessary (nebula reloads certificates
// hot) and disruptive. Restart only when the change requires it, which in
// practice means a changed overlay address: nebula rejects a reload whose
// certificate networks differ.
type CommandReloader struct {
	Args []string
}

func (r CommandReloader) Reload(ctx context.Context) error {
	if len(r.Args) == 0 {
		return nil
	}
	cmd := exec.CommandContext(ctx, r.Args[0], r.Args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(r.Args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r CommandReloader) Describe() string { return strings.Join(r.Args, " ") }

// ParseReloader builds a Reloader from a flag value:
//
//	""                 no reload
//	"pid:/path"        SIGHUP the pid in /path
//	anything else      run it as a command
func ParseReloader(spec string) Reloader {
	switch {
	case spec == "":
		return NoopReloader{}
	case strings.HasPrefix(spec, "pid:"):
		return SignalReloader{PidFile: strings.TrimPrefix(spec, "pid:")}
	default:
		return CommandReloader{Args: strings.Fields(spec)}
	}
}

// ReloaderFunc adapts a function to the Reloader interface. Useful for tests
// and for embedding the agent in a process that owns nebula itself.
type ReloaderFunc struct {
	Name string
	Fn   func() error
}

func (r ReloaderFunc) Reload(context.Context) error { return r.Fn() }

func (r ReloaderFunc) Describe() string {
	if r.Name == "" {
		return "func"
	}
	return r.Name
}
