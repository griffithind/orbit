package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/mesh"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The control plane is a mesh member, so it needs the same configuration
// updates every other host gets.
//
// Rendering its configuration once at startup — which is what it used to do —
// leaves it with a frozen trust bundle, blocklist, and lighthouse list. The
// visible symptom is a stale lighthouse address, but the serious ones are
// silent: after a CA rotation it rejects every host that renewed onto the new
// CA, and after a block it keeps trusting the blocked host.

func (h *harness) joinControlPlane(t *testing.T, addr string, agentPort int) (*mesh.Node, *enroll.Service) {
	t.Helper()

	hasher, err := enroll.NewHasher([]byte(strings.Repeat("pepper-for-tests", 4)))
	if err != nil {
		t.Fatal(err)
	}
	registry := ca.NewRegistry(ca.FileSignerFactory)
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, hasher, enroll.Config{
		Paths:      nebulacfg.DefaultPaths(),
		ListenPort: freeUDPPort(t),
	})

	node, err := mesh.Join(context.Background(), svc, mesh.Config{
		NetworkID: h.netID,
		Addr:      mustAddr(addr),
		AgentPort: agentPort,
	}, slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("control plane could not join: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node, svc
}

// TestControlPlanePicksUpANewCA is the serious case. After a rotation the
// control plane must trust the new CA, or every host that renews onto it stops
// being able to reach the agent API — which is where renewals happen.
func TestControlPlanePicksUpANewCA(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	// A lighthouse, so the control plane's config has something to render.
	lhPort := freeUDPPort(t)
	h.createAndEnroll(t, ts, "lh-refresh", "10.42.60.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})

	node, svc := h.joinControlPlane(t, "10.42.60.2", 8450)

	before, _, err := svc.ControlPlaneMaterial(ctx, node.HostID())
	if err != nil {
		t.Fatalf("initial material: %v", err)
	}
	_ = before

	_, bundleBefore, _ := svc.ControlPlaneMaterial(ctx, node.HostID())
	if countPEMBlocks(bundleBefore) != 1 {
		t.Fatalf("expected one CA to start with, got %d", countPEMBlocks(bundleBefore))
	}

	// Rotate: creating a CA publishes it, which advances the config epoch.
	ca2 := h.createCA(t, ts.URL, "refresh-ca-2")
	if code := h.adminPost(t, ts.URL+"/v1/cas/"+ca2.ID+"/activate",
		wire.ActivateCARequest{AcknowledgeCutoff: true}, nil); code != http.StatusOK {
		t.Fatalf("activate: %d", code)
	}

	// A refresh must pick the new CA up.
	if err := node.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	_, bundleAfter, err := svc.ControlPlaneMaterial(ctx, node.HostID())
	if err != nil {
		t.Fatal(err)
	}
	if countPEMBlocks(bundleAfter) < 2 {
		t.Fatalf("control plane trust bundle has %d CAs after a rotation, want both",
			countPEMBlocks(bundleAfter))
	}
	t.Logf("control plane trust bundle: %d -> %d CAs",
		countPEMBlocks(bundleBefore), countPEMBlocks(bundleAfter))
}

// TestControlPlanePicksUpABlocklistEntry covers the other silent case: a
// control plane running a frozen configuration keeps trusting a host everyone
// else has stopped trusting.
func TestControlPlanePicksUpABlocklistEntry(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	lhPort := freeUDPPort(t)
	h.createAndEnroll(t, ts, "lh-block", "10.42.61.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})
	victim := h.createAndEnroll(t, ts, "to-block", "10.42.61.7", false, false, nil)

	node, svc := h.joinControlPlane(t, "10.42.61.2", 8451)

	cfgBefore, _, err := svc.ControlPlaneMaterial(ctx, node.HostID())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfgBefore, "blocklist:\n        - ") {
		t.Fatal("blocklist is not empty to begin with")
	}

	var blocked wire.BlockResponse
	if code := h.adminPost(t, ts.URL+"/v1/hosts/"+victim.id+"/block", nil, &blocked); code != http.StatusOK {
		t.Fatalf("block: %d", code)
	}

	if err := node.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	cfgAfter, _, err := svc.ControlPlaneMaterial(ctx, node.HostID())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfgAfter, "blocklist:\n        - ") {
		t.Errorf("control plane configuration has no blocklist entry after a block:\n%s", cfgAfter)
	}
}

// TestControlPlanePicksUpANewLighthouse is the visible case from the
// deployment guide: adding a lighthouse used to require restarting orbitd.
func TestControlPlanePicksUpANewLighthouse(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	firstPort := freeUDPPort(t)
	h.createAndEnroll(t, ts, "lh-one", "10.42.62.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", firstPort)})

	node, svc := h.joinControlPlane(t, "10.42.62.2", 8452)

	// A second lighthouse, added after the control plane was already running.
	secondPort := freeUDPPort(t)
	h.createAndEnroll(t, ts, "lh-two", "10.42.62.3", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", secondPort)})

	if err := node.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	cfg, _, err := svc.ControlPlaneMaterial(ctx, node.HostID())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "10.42.62.3") {
		t.Errorf("control plane did not pick up the second lighthouse:\n%s", cfg)
	}
	// And it must still not point at itself.
	if strings.Contains(cfg, "10.42.62.2") {
		t.Error("control plane listed itself as a lighthouse")
	}
}

// TestMaintainRefreshesOnEpochChange proves the wiring, not just the method: a
// change to the network must reach the running node without anyone calling
// Refresh by hand.
func TestMaintainRefreshesOnEpochChange(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lhPort := freeUDPPort(t)
	h.createAndEnroll(t, ts, "lh-maintain", "10.42.63.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})

	node, svc := h.joinControlPlane(t, "10.42.63.2", 8453)

	changes := make(chan struct{}, 1)
	go node.Maintain(ctx, changes, time.Hour) // timer far away; only the signal fires

	// Add a lighthouse, then signal the way the notifier would.
	newPort := freeUDPPort(t)
	h.createAndEnroll(t, ts, "lh-maintain-2", "10.42.63.4", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", newPort)})
	changes <- struct{}{}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cfg, _, err := svc.ControlPlaneMaterial(ctx, node.HostID())
		if err == nil && strings.Contains(cfg, "10.42.63.4") {
			t.Log("control plane refreshed itself on an epoch change")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("Maintain did not refresh after an epoch change")
}

// TestControlPlaneAsLighthouse covers the single-VM topology: the control plane
// is the lighthouse, so there is nothing else to install and no ordering
// problem during bring-up.
func TestControlPlaneAsLighthouse(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	cpPort := freeUDPPort(t)
	hasher, err := enroll.NewHasher([]byte(strings.Repeat("pepper-for-tests", 4)))
	if err != nil {
		t.Fatal(err)
	}
	registry := ca.NewRegistry(ca.FileSignerFactory)
	t.Cleanup(func() { registry.Close() })
	svc := enroll.NewService(h.store, registry, hasher, enroll.Config{
		Paths: nebulacfg.DefaultPaths(), ListenPort: freeUDPPort(t),
	})

	public := fmt.Sprintf("127.0.0.1:%d", cpPort)
	node, err := mesh.Join(ctx, svc, mesh.Config{
		NetworkID: h.netID, Addr: mustAddr("10.42.64.1"),
		AgentPort: 8454, ListenPort: cpPort,
		LighthouseAddrs: []string{public},
	}, slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("join as lighthouse: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })

	// Every other host must now be told to use it — that only happens if the
	// role reached the host record, which is what topology is rendered from.
	host := h.createAndEnroll(t, ts, "uses-cp-lighthouse", "10.42.64.7", false, false, nil)
	cfg := readFile(t, agent.DefaultLayout(host.dir).ConfigPath())
	if !strings.Contains(cfg, "10.42.64.1") || !strings.Contains(cfg, public) {
		t.Fatalf("host was not told to use the control plane as a lighthouse:\n%s", cfg)
	}

	// Handing the role to a dedicated lighthouse must propagate: the record
	// changes, the epoch advances, and hosts stop listing this address.
	lhPort := freeUDPPort(t)
	h.createAndEnroll(t, ts, "dedicated-lh", "10.42.64.9", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})

	err = h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.SetHostRoles(ctx, node.HostID(), false, false, nil)
	})
	if err != nil {
		t.Fatalf("stand down as lighthouse: %v", err)
	}

	after, _, err := svc.ControlPlaneMaterial(ctx, node.HostID())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(after, public) {
		t.Error("control plane still advertises itself after standing down")
	}
	if !strings.Contains(after, "10.42.64.9") {
		t.Errorf("control plane did not pick up the dedicated lighthouse:\n%s", after)
	}
}

// TestLighthouseRoleChangesWithoutRestart is the point of driving roles from
// the host record rather than from flags: moving the lighthouse is an API call,
// and the control plane reconfigures itself.
func TestLighthouseRoleChangesWithoutRestart(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	ctx := context.Background()

	cpPort := freeUDPPort(t)
	public := fmt.Sprintf("127.0.0.1:%d", cpPort)

	hasher, err := enroll.NewHasher([]byte(strings.Repeat("pepper-for-tests", 4)))
	if err != nil {
		t.Fatal(err)
	}
	registry := ca.NewRegistry(ca.FileSignerFactory)
	t.Cleanup(func() { registry.Close() })
	svc := enroll.NewService(h.store, registry, hasher, enroll.Config{
		Paths: nebulacfg.DefaultPaths(), ListenPort: freeUDPPort(t),
	})

	node, err := mesh.Join(ctx, svc, mesh.Config{
		NetworkID: h.netID, Addr: mustAddr("10.42.65.1"),
		AgentPort: 8455, ListenPort: cpPort,
		LighthouseAddrs: []string{public},
	}, slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })

	roles, err := node.Roles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !roles.IsLighthouse || !roles.SeededThisStart {
		t.Fatalf("seeded roles did not take on first start: %+v", roles)
	}

	// A dedicated lighthouse, then stand the control plane down — through the
	// API, with no restart and no flag change.
	lhPort := freeUDPPort(t)
	dedicated := h.createAndEnroll(t, ts, "dedicated", "10.42.65.9", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})
	_ = dedicated

	no := false
	if code := h.adminReq(t, http.MethodPatch, ts.URL+"/v1/hosts/"+node.HostID().String(),
		wire.UpdateHostRequest{IsLighthouse: &no, StaticAddrs: &[]string{}}, nil); code != http.StatusOK {
		t.Fatalf("stand down via API: %d", code)
	}

	if err := node.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	roles, err = node.Roles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if roles.IsLighthouse {
		t.Error("control plane still reports itself a lighthouse after the API change")
	}

	cfg, _, err := svc.ControlPlaneMaterial(ctx, node.HostID())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, public) {
		t.Error("control plane still advertises its own address")
	}
	if !strings.Contains(cfg, "10.42.65.9") {
		t.Errorf("control plane did not adopt the dedicated lighthouse:\n%s", cfg)
	}
}

// TestLighthouseRequiresAnAddress: a lighthouse nobody can reach is worse than
// none, because every host keeps dialling it.
func TestLighthouseRequiresAnAddress(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "no-addr", "10.42.66.5", false, false, nil)

	yes := true
	if code := h.adminReq(t, http.MethodPatch, ts.URL+"/v1/hosts/"+host.id,
		wire.UpdateHostRequest{IsLighthouse: &yes}, nil); code != http.StatusBadRequest {
		t.Errorf("making a host a lighthouse with no address = %d, want 400", code)
	}
}
