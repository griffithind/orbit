package agent

import (
	"context"
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
	// Ensure starts nebula if it is not running, and reports whether it had to.
	//
	// On the interface rather than on the concrete supervisor because it is what
	// makes a host self-healing, and a self-healing property that only one
	// implementation has is a property the loop cannot rely on. A nebula that
	// failed to start at boot would otherwise stay down until a NEW generation
	// arrived from the control plane, which on a settled network is never.
	Ensure(ctx context.Context) (started bool, err error)
	// Describe is used in logs so an operator can see what the agent will
	// actually do without reading its flags.
	Describe() string
}

// SupervisorFuncs adapts functions to Supervisor, for tests and for embedding
// the agent in a process that owns nebula itself.
type SupervisorFuncs struct {
	Name      string
	RestartFn func(ctx context.Context) error
	StatusFn  func(ctx context.Context) (Status, error)
	EnsureFn  func(ctx context.Context) (bool, error)
}

func (s SupervisorFuncs) Restart(ctx context.Context) error {
	if s.RestartFn == nil {
		return nil
	}
	return s.RestartFn(ctx)
}

// Ensure defaults to "already running, nothing to do" rather than to Restart:
// a nil EnsureFn means the caller did not model starting, and starting nebula
// under a test that did not ask for it is worse than not starting it.
func (s SupervisorFuncs) Ensure(ctx context.Context) (bool, error) {
	if s.EnsureFn == nil {
		return false, nil
	}
	return s.EnsureFn(ctx)
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

const (
	restartSettleDefault = 45 * time.Second
	restartPollDefault   = 500 * time.Millisecond
)
