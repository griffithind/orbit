package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
)

// Nebula, run inside the agent rather than supervised as a separate process.
//
// WHAT THIS TRADES. One binary and one unit per host: no nebula to install, no
// PATH to get wrong, no -restart spec naming a systemd instance, no version skew
// between the configuration Orbit renders and the binary that loads it. Against
// that, an agent crash now takes the data plane with it, where two processes
// under two units failed independently.
//
// The property people usually mean by "the data plane survives" is unaffected:
// a control plane outage still leaves every host holding its certificate and its
// tunnels, because nothing in that path involves the control plane. What changes
// is narrower — agent liveness and tunnel liveness are now the same liveness,
// bounded by however fast the service manager restarts it.
//
// Embedded satisfies both Reloader and Supervisor, so everything above it — the
// apply sequence, the revert guard, verification — is unchanged and untested
// code paths are not introduced alongside the ones that already work.
type Embedded struct {
	// ConfigArg is what nebula is pointed at, and it is Layout.NebulaConfigArg
	// rather than Layout.ConfigPath — a FILE in authoritative mode and a
	// DIRECTORY in fragment mode.
	//
	// The distinction is the whole point of the modes: nebula loads a file
	// verbatim and merges a directory. Handing it ConfigPath would load the
	// fragment alone on a fragment-mode host, silently dropping every
	// operator-authored file the mode exists to include.
	ConfigArg string

	Log *slog.Logger

	mu   sync.Mutex
	c    *config.C
	ctrl *nebula.Control
	// generation increments on every start, and is what Status reports as the
	// instance token. A supervised process needs pid plus kernel start time to
	// survive pid reuse; here the engine performs the restart itself, so a
	// counter is both simpler and exact.
	generation uint64
	running    bool
}

var (
	_ Reloader   = (*Embedded)(nil)
	_ Supervisor = (*Embedded)(nil)
)

// StopGrace bounds how long a restart waits for the previous nebula to finish.
//
// Bounded for the reason every wait in this codebase is: nebula's shutdown
// completes when every reader goroutine has exited and the interface has
// released its construction token, and a teardown race that parks one of them
// makes the wait never return. An agent that cannot finish restarting is an
// agent that never applies anything again.
const StopGrace = 15 * time.Second

func (e *Embedded) Describe() string { return "nebula (embedded)" }

// Start brings nebula up. Safe to call when it is already running, which is a
// no-op rather than a second instance.
func (e *Embedded) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.startLocked(ctx)
}

func (e *Embedded) startLocked(_ context.Context) error {
	if e.running {
		return nil
	}

	log := e.Log
	if log == nil {
		log = discardLogger()
	}
	nlog := log.With("component", "nebula")

	c := config.NewC(nlog)
	if err := c.Load(e.ConfigArg); err != nil {
		return fmt.Errorf("load %s: %w", e.ConfigArg, err)
	}

	// A nil device factory means the real tun device, which is the whole
	// difference between this and internal/mesh: the control plane runs on a
	// userspace stack and needs no interface, a managed host IS the interface.
	// It is also why this path needs root.
	ctrl, err := nebula.Main(c, false, "orbit-agent", nlog, nil)
	if err != nil {
		return fmt.Errorf("nebula rejected the configuration: %w", err)
	}
	if err := ctrl.Start(); err != nil {
		return fmt.Errorf("start nebula: %w", err)
	}

	e.c, e.ctrl, e.running = c, ctrl, true
	e.generation++
	log.Info("nebula started", "generation", e.generation, "config", e.ConfigArg)
	return nil
}

// Reload re-reads the configuration file, which is what the agent has just
// rewritten. The equivalent of the SIGHUP a supervised nebula would receive.
func (e *Embedded) Reload(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		// Nothing to reload into. Starting is the correct response rather than
		// an error: the agent applied a generation and something has to be
		// running it, and refusing here would leave a host with a current
		// configuration and no data plane.
		return e.startLocked(ctx)
	}
	e.c.ReloadConfig()
	return nil
}

// Restart replaces the running instance, for the changes nebula cannot take on
// a reload — an overlay address change, which it refuses because the
// certificate's networks differ.
//
// In-process, this is a stop and a start rather than a conversation with a
// service manager, and the restart is verifiable by construction: the engine
// performed it, so Status reports a new generation without having to prove
// anything about pids.
func (e *Embedded) Restart(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stopLocked()
	return e.startLocked(ctx)
}

func (e *Embedded) stopLocked() {
	if !e.running {
		return
	}

	ctrl := e.ctrl
	e.ctrl, e.c, e.running = nil, nil, false

	done := make(chan struct{})
	go func() {
		ctrl.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(StopGrace):
		// Abandoned rather than waited on. The goroutines belong to an instance
		// that is being replaced, and blocking here would stop the agent from
		// ever applying anything again — which is worse than leaking them until
		// the process exits.
		if e.Log != nil {
			e.Log.Warn("nebula did not finish stopping; continuing", "waited", StopGrace)
		}
	}
}

// Status reports whether nebula is up and which run this is.
//
// Known is always true. That is the substantive difference from a supervised
// nebula, where the agent may be unable to observe the process at all and must
// say so rather than guess: here the engine owns it, so "is it running" has an
// exact answer and a restart can always be verified.
func (e *Embedded) Status(context.Context) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Status{
		Known:    true,
		Running:  e.running,
		Instance: fmt.Sprintf("gen-%d", e.generation),
	}, nil
}

// Close stops nebula. Idempotent.
func (e *Embedded) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
	return nil
}

// ErrNotEmbedded is returned by helpers that only make sense for an engine that
// owns nebula.
var ErrNotEmbedded = errors.New("nebula is not embedded in this agent")
