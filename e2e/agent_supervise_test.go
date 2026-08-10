package e2e

// Supervision, end to end against a real control plane.
//
// The bug these exist for is a mechanism complete on one side and never
// triggered from the other. Nebula refuses a certificate reload whose Networks
// differ (pki.go reloadCerts); the agent knew that and asked for a restart, but
// nothing checked whether the restart happened. A restart that silently did not
// happen leaves the host running its OLD certificate — which is valid,
// unrevoked, and perfectly able to reach the control plane — until it expires.
// No probe the agent can run end to end distinguishes that from success. Only
// the process changing does.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/agent/dataplane"
	"github.com/griffithind/orbit/internal/agent/generation"
	"github.com/griffithind/orbit/internal/agent/paths"
)

// scriptedSupervisor stands in for a service manager. take reports whether the
// restart actually replaces the process.
type scriptedSupervisor struct {
	mu       sync.Mutex
	instance string
	running  bool
	take     bool
	restarts int
	failWith error
}

func newScriptedSupervisor(take bool) *scriptedSupervisor {
	return &scriptedSupervisor{instance: "run-1", running: true, take: take}
}

func (s *scriptedSupervisor) supervisor() dataplane.Supervisor {
	return dataplane.SupervisorFuncs{
		Name: "scripted",
		StatusFn: func(context.Context) (dataplane.Status, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			return dataplane.Status{
				Known: true, Running: s.running, Instance: s.instance,
				Detail: "scripted " + s.instance,
			}, nil
		},
		RestartFn: func(context.Context) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.restarts++
			if s.failWith != nil {
				return s.failWith
			}
			if s.take {
				// A NEW token every time. Reusing one would make the second
				// restart in a test look like a restart that did not happen,
				// which is precisely what these tests are here to distinguish.
				s.instance = fmt.Sprintf("run-%d", s.restarts+1)
				s.running = true
			}
			return nil
		},
	}
}

func (s *scriptedSupervisor) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restarts
}

// reAddressed fabricates the generation an operator's address change would
// produce: this host's configuration, carrying a certificate (and matching key)
// for a different overlay address.
func reAddressed(t *testing.T, h *harness, ts *httptest.Server, host *enrolledHost, name, addr string) generation.Material {
	t.Helper()
	other := h.createAndEnroll(t, ts, name, addr, false, false, nil)
	l, ol := paths.DefaultLayout(host.dir), paths.DefaultLayout(other.dir)
	return generation.Material{
		Config:      readFile(t, l.ConfigPath()),
		CABundle:    readFile(t, l.Paths.CA),
		Certificate: readFile(t, ol.Paths.Cert),
		PrivateKey:  readFile(t, ol.Paths.Key),
	}
}

func quietApplier(layout paths.Layout, sup dataplane.Supervisor) *generation.Applier {
	return &generation.Applier{
		Layout:     layout,
		Reloader:   generation.NoopReloader{},
		Supervisor: sup,
		// Short, and deliberately so: every failing case here is a supervisor
		// that will NEVER satisfy the check, so the deadline is one the test
		// expects to expire. A slower machine makes it slower, never green.
		RestartSettle: 100 * time.Millisecond,
		RestartPoll:   2 * time.Millisecond,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// TestAddressChangeRestartsAndIsApplied is the happy path that never previously
// ran: with a supervisor that really replaces the process, the new certificate
// is installed and kept.
func TestAddressChangeRestartsAndIsApplied(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "readdress-ok", "10.42.6.5", false, false, nil)

	layout := paths.DefaultLayout(host.dir)
	before := readFile(t, layout.Paths.Cert)
	m := reAddressed(t, h, ts, host, "readdress-ok-other", "10.42.6.6")

	sup := newScriptedSupervisor(true)
	if err := quietApplier(layout, sup.supervisor()).Apply(context.Background(), m); err != nil {
		t.Fatalf("apply an address change with a working supervisor: %v", err)
	}
	if sup.count() != 1 {
		t.Errorf("restarted %d times, want exactly 1", sup.count())
	}
	if got := readFile(t, layout.Paths.Cert); got == before {
		t.Error("the new certificate was not installed")
	}
}

// TestRestartThatDoesNotTakeIsRolledBack is the core case. The supervisor exits
// zero and changes nothing — exactly what a masked unit, a unit pointing at
// another network's directory, or a reload-instead-of-restart looks like.
func TestRestartThatDoesNotTakeIsRolledBack(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "readdress-noop", "10.42.6.9", false, false, nil)

	layout := paths.DefaultLayout(host.dir)
	before := readFile(t, layout.Paths.Cert)
	m := reAddressed(t, h, ts, host, "readdress-noop-other", "10.42.6.10")

	sup := newScriptedSupervisor(false) // exits zero, replaces nothing
	err := quietApplier(layout, sup.supervisor()).Apply(context.Background(), m)
	if !errors.Is(err, generation.ErrRestartFailed) {
		t.Fatalf("apply error = %v, want ErrRestartFailed", err)
	}
	if got := readFile(t, layout.Paths.Cert); got != before {
		t.Error("a certificate nebula is not running was left installed; " +
			"this host would drop off the mesh at expiry for no visible reason")
	}
}

// TestAddressChangeStillRefusedWithoutSupervisor keeps the pre-existing guard:
// refusing is better than installing a certificate that will be ignored.
func TestAddressChangeStillRefusedWithoutSupervisor(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "readdress-none", "10.42.6.13", false, false, nil)

	layout := paths.DefaultLayout(host.dir)
	before := readFile(t, layout.Paths.Cert)
	m := reAddressed(t, h, ts, host, "readdress-none-other", "10.42.6.14")

	err := quietApplier(layout, nil).Apply(context.Background(), m)
	if !errors.Is(err, generation.ErrRestartRequired) {
		t.Fatalf("apply error = %v, want ErrRestartRequired", err)
	}
	if got := readFile(t, layout.Paths.Cert); got != before {
		t.Error("the refused generation was installed anyway")
	}
}

// TestRevertAcrossAnAddressChangeRestarts is the same bug in the other
// direction, and it was live: the unreachable-guard restored the previous
// generation and only ever sent SIGHUP. Going BACK across an address change is
// exactly as un-hot-loadable as going forward, so nebula would refuse it and
// keep running the generation that broke the host — while the agent reported
// itself reverted.
func TestRevertAcrossAnAddressChangeRestarts(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "revert-readdress", "10.42.6.17", false, false, nil)

	layout := paths.DefaultLayout(host.dir)
	original := readFile(t, layout.Paths.Cert)
	m := reAddressed(t, h, ts, host, "revert-readdress-other", "10.42.6.18")

	sup := newScriptedSupervisor(true)
	a := quietApplier(layout, sup.supervisor())
	if err := a.Apply(context.Background(), m); err != nil {
		t.Fatalf("apply: %v", err)
	}
	restartsAfterApply := sup.count()

	if err := a.Revert(context.Background()); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if sup.count() == restartsAfterApply {
		t.Error("revert crossed an address change without restarting nebula; " +
			"the host is still running the generation the guard tried to undo")
	}
	if got := readFile(t, layout.Paths.Cert); got != original {
		t.Error("revert did not restore the original certificate")
	}
}

// TestAuthoritativeModeInstallsExactlyOneConfigFile is the merge-removal check.
// Nebula merges a config DIRECTORY with mergo.WithAppendSlice, concatenating
// firewall rules across files; pointing it at a single file is what makes Orbit
// authoritative, and that only holds if the agent writes no directory.
func TestAuthoritativeModeInstallsExactlyOneConfigFile(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "authoritative", "10.42.6.21", false, false, nil)

	layout := paths.DefaultLayout(host.dir)
	if filepath.Base(layout.ConfigPath()) != "nebula.yml" {
		t.Fatalf("authoritative config is %q", layout.ConfigPath())
	}
	if _, err := os.Stat(layout.ConfigPath()); err != nil {
		t.Fatalf("nebula.yml was not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(host.dir, "config.d")); !os.IsNotExist(err) {
		t.Error("a config.d directory exists in authoritative mode; nebula would merge it")
	}
	// The contract the control-plane renderer and the systemd units are written
	// against.
	for _, name := range []string{"nebula.yml", "ca.crt", "host.crt", "host.key", "agent.json"} {
		if _, err := os.Stat(filepath.Join(host.dir, name)); err != nil {
			t.Errorf("%s missing from the per-network directory: %v", name, err)
		}
	}
}

// TestPerNetworkDirectoriesShareNothing is the multi-instance property stated as
// a test: two networks on one host must not be able to touch each other's
// state, even when both agents are running against the same root.
func TestPerNetworkDirectoriesShareNothing(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	root := t.TempDir()
	seen := map[string]string{}
	for _, net := range []struct{ slug, addr string }{{"prod", "10.42.6.29"}, {"staging", "10.42.6.30"}} {
		src := h.createAndEnroll(t, ts, "multi-"+net.slug, net.addr, false, false, nil)
		dir := filepath.Join(root, net.slug)
		layout := paths.DefaultLayout(dir)
		s := paths.DefaultLayout(src.dir)
		if err := quietApplier(layout, nil).Apply(context.Background(), generation.Material{
			Config:      readFile(t, s.ConfigPath()),
			CABundle:    readFile(t, s.Paths.CA),
			Certificate: readFile(t, s.Paths.Cert),
			PrivateKey:  readFile(t, s.Paths.Key),
		}); err != nil {
			t.Fatalf("apply for %s: %v", net.slug, err)
		}
		if layout.Network != net.slug {
			t.Errorf("network label = %q, want %q", layout.Network, net.slug)
		}
		for _, p := range []string{layout.ConfigPath(), layout.Paths.Cert, layout.Paths.Key,
			layout.StatePath(), layout.PreviousDir()} {
			if other, ok := seen[p]; ok {
				t.Fatalf("%s is shared with %s", p, other)
			}
			seen[p] = net.slug
		}
	}

	// Each network's certificate is its own.
	a := readFile(t, paths.DefaultLayout(filepath.Join(root, "prod")).Paths.Cert)
	b := readFile(t, paths.DefaultLayout(filepath.Join(root, "staging")).Paths.Cert)
	if a == b {
		t.Error("two networks on one host ended up with the same certificate")
	}
}
