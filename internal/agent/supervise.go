package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Supervision, as opposed to signalling.
//
// The agent does not own nebula's lifecycle — the service manager does, and
// that is deliberate: an agent crash must not take down the data plane. But
// "does not own" was implemented as "does not look", and that left two holes.
//
// The first is the address change. Nebula refuses a certificate reload whose
// Networks or Curve differ from the running ones (pki.go reloadCerts). A host
// whose overlay address changes therefore installs a new certificate, gets the
// reload REFUSED, logs one line, and keeps running the old certificate until it
// expires — at which point the host drops off the mesh for reasons that look
// nothing like "its address changed". Only a process restart applies it, and a
// restart has to be VERIFIED, because a restart that silently did not happen is
// indistinguishable from one that did if nobody checks.
//
// The second is liveness. With Restart=always, systemd restarts a crashing
// nebula and the agent never notices; a host that cannot start at all reports
// nothing and looks, from the control plane, exactly like a host that is fine.
//
// A Supervisor closes both. It restarts on demand and it can say whether nebula
// is running and WHICH RUN is running, which is the only locally available
// proof that a restart took effect.

// Status is what the agent can observe about the nebula process for its network.
type Status struct {
	// Known is false when this supervisor cannot observe the process at all.
	//
	// Not the same as "not running", and conflating the two would be the worst
	// possible error: it would report every host with an unobservable supervisor
	// as down, and it would let an unverifiable restart pass as verified.
	Known bool

	// Running is meaningful only when Known.
	Running bool

	// Instance identifies THIS run of nebula. It changes when, and only when,
	// the process is replaced.
	//
	// This is the restart proof. Reachability is not: a host still running its
	// OLD certificate after a refused reload holds a valid, unrevoked
	// certificate for its OLD address and can reach the control plane perfectly
	// well, so an end-to-end probe reports success for exactly the failure it is
	// meant to catch. A changed instance token, on the other hand, means the
	// running process started AFTER the new files were installed, and nebula
	// reads its configuration at startup — so it cannot be running anything else.
	Instance string

	// Detail is for logs: whatever the supervisor knows in human terms.
	Detail string
}

// Supervisor restarts nebula and reports whether it is running.
type Supervisor interface {
	Status(ctx context.Context) (Status, error)
	Restart(ctx context.Context) error
	// Describe is used in logs so an operator can see what the agent will
	// actually do without reading its flags.
	Describe() string
}

// SystemdSupervisor drives one templated nebula instance.
//
// Unit MUST name the instance — "nebula@prod.service", never "nebula". A host
// on two networks has two units, and a supervisor that targets the bare unit
// name would restart the wrong network's data plane, or none.
type SystemdSupervisor struct {
	Unit string

	// systemctl is injectable for tests.
	systemctl func(ctx context.Context, args ...string) ([]byte, error)
}

func NewSystemdSupervisor(unit string) *SystemdSupervisor {
	if !strings.Contains(unit, ".") {
		unit += ".service"
	}
	return &SystemdSupervisor{Unit: unit}
}

func (s *SystemdSupervisor) run(ctx context.Context, args ...string) ([]byte, error) {
	if s.systemctl != nil {
		return s.systemctl(ctx, args...)
	}
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (s *SystemdSupervisor) Describe() string { return "systemctl restart " + s.Unit }

func (s *SystemdSupervisor) Restart(ctx context.Context) error {
	_, err := s.run(ctx, "restart", s.Unit)
	return err
}

// Status reads the unit's state.
//
// ExecMainStartTimestampMonotonic is the instance token: it is systemd's own
// record of when the current main process started, so it changes on every
// restart and cannot be confused by pid reuse. MainPID is carried alongside it
// for the log line, not for the comparison.
func (s *SystemdSupervisor) Status(ctx context.Context) (Status, error) {
	out, err := s.run(ctx, "show", s.Unit,
		"--property=ActiveState", "--property=SubState",
		"--property=MainPID", "--property=ExecMainStartTimestampMonotonic")
	if err != nil {
		return Status{}, err
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			props[k] = v
		}
	}

	pid := props["MainPID"]
	started := props["ExecMainStartTimestampMonotonic"]
	running := props["ActiveState"] == "active" && pid != "" && pid != "0"

	st := Status{
		Known:   true,
		Running: running,
		Detail: fmt.Sprintf("%s %s/%s pid %s",
			s.Unit, props["ActiveState"], props["SubState"], pid),
	}
	if running {
		st.Instance = pid + "@" + started
	}
	return st, nil
}

// CommandSupervisor is the escape hatch for a host that is not running systemd.
//
// Restart runs whatever command the operator configured. Liveness comes from a
// pidfile, which is optional — and when it is absent this supervisor reports
// Known=false, because a supervisor that guessed "running" would silently
// convert an unverifiable restart into a verified one.
type CommandSupervisor struct {
	Args    []string
	PidFile string
}

func (c CommandSupervisor) Describe() string {
	d := strings.Join(c.Args, " ")
	if c.PidFile != "" {
		d += " (liveness via " + c.PidFile + ")"
	}
	return d
}

func (c CommandSupervisor) Restart(ctx context.Context) error {
	if len(c.Args) == 0 {
		return errors.New("no restart command configured")
	}
	out, err := exec.CommandContext(ctx, c.Args[0], c.Args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(c.Args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (c CommandSupervisor) Status(ctx context.Context) (Status, error) {
	if c.PidFile == "" {
		return Status{Known: false, Detail: "no pidfile; nebula liveness is not observable"}, nil
	}
	b, err := os.ReadFile(c.PidFile)
	if err != nil {
		if os.IsNotExist(err) {
			// A missing pidfile is a real observation, not an unknown: the
			// process manager writes it at start and removes it at stop.
			return Status{Known: true, Running: false, Detail: "pidfile " + c.PidFile + " does not exist"}, nil
		}
		return Status{}, fmt.Errorf("read pidfile: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return Status{}, fmt.Errorf("parse pidfile %q: %w", c.PidFile, err)
	}
	instance, alive := processInstance(pid)
	return Status{
		Known:    true,
		Running:  alive,
		Instance: instance,
		Detail:   fmt.Sprintf("pid %d from %s", pid, c.PidFile),
	}, nil
}

// SupervisorFuncs adapts functions to Supervisor, for tests and for embedding
// the agent in a process that owns nebula itself.
type SupervisorFuncs struct {
	Name      string
	RestartFn func(ctx context.Context) error
	StatusFn  func(ctx context.Context) (Status, error)
}

func (s SupervisorFuncs) Restart(ctx context.Context) error {
	if s.RestartFn == nil {
		return nil
	}
	return s.RestartFn(ctx)
}

func (s SupervisorFuncs) Status(ctx context.Context) (Status, error) {
	if s.StatusFn == nil {
		return Status{}, nil
	}
	return s.StatusFn(ctx)
}

func (s SupervisorFuncs) Describe() string {
	if s.Name == "" {
		return "func"
	}
	return s.Name
}

// ParseSupervisor builds a Supervisor from the -restart flag:
//
//	""                       nil: restarts are refused and liveness is unknown
//	"unit:nebula@prod"       systemctl restart/show against that instance
//	anything else            run it as a command
//
// pidFile, when non-empty, gives the command form something to observe. It is
// taken from the -reload flag rather than being a flag of its own, because a
// host that reloads by pidfile has exactly one pidfile and naming it twice is
// one more thing to get out of step.
func ParseSupervisor(spec, pidFile string) Supervisor {
	switch {
	case spec == "":
		return nil
	case strings.HasPrefix(spec, "unit:"):
		return NewSystemdSupervisor(strings.TrimPrefix(spec, "unit:"))
	default:
		return CommandSupervisor{Args: strings.Fields(spec), PidFile: pidFile}
	}
}

// PidFileFromReloadSpec extracts the pidfile from a -reload value, or "".
func PidFileFromReloadSpec(spec string) string {
	if strings.HasPrefix(spec, "pid:") {
		return strings.TrimPrefix(spec, "pid:")
	}
	return ""
}

// processInstance builds a token that identifies one run of a process, and
// reports whether it is alive.
//
// On Linux the token includes the kernel's start time for the pid, which makes
// it immune to pid reuse. Elsewhere there is no portable way to get that
// without a dependency, and the pid alone is still a usable token: the failure
// it misses is "nebula restarted AND the new process was handed the same pid",
// which requires the whole pid space to wrap between two polls a second apart.
func processInstance(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return "", false
	}
	if err := p.Signal(syscall.Signal(0)); err != nil {
		return "", false
	}
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		// The comm field is parenthesised and may itself contain spaces, so
		// fields are counted from the last ')' rather than from the start.
		if i := bytes.LastIndexByte(b, ')'); i >= 0 {
			f := strings.Fields(string(b[i+1:]))
			if len(f) >= 20 {
				return strconv.Itoa(pid) + "@" + f[19], true
			}
		}
	}
	return strconv.Itoa(pid), true
}

// restartSettleDefault bounds how long the agent waits for a restart to show up
// as a new process.
//
// Generous, because it covers systemd's stop timeout plus nebula's startup, and
// the cost of waiting is only a slower rollback on a host whose tunnels are
// already down. Too short would be far worse: it would roll back healthy
// restarts on a loaded host, turning an address change into a flap.
const (
	restartSettleDefault = 45 * time.Second
	restartPollDefault   = 500 * time.Millisecond
)
