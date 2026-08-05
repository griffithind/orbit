package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"testing"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/mesh"
	"github.com/griffithind/orbit/internal/nebulacfg"
)

// TestMeshJoinCost measures what one joined network costs a control-plane
// process, because that is the binding constraint on how many networks a single
// orbitd can serve.
//
// Rows cost nothing. Networks are only expensive when orbitd JOINS them: each
// join is a full nebula instance with its own UDP socket, userspace network
// stack, hostmap, and timer goroutines. A network orbitd does not join still
// enrolls hosts and serves admin requests; it simply has no agent API.
//
// Run with -v to see the numbers.
func TestMeshJoinCost(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates several nebula stacks")
	}

	const networks = 4

	h := setup(t)
	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      0,
	})

	settle := func() (goroutines int, heapMB float64) {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return runtime.NumGoroutine(), float64(m.HeapAlloc) / (1 << 20)
	}

	g0, h0 := settle()

	var nodes []*mesh.Node
	for i := 0; i < networks; i++ {
		// Each network needs its own CA and prefix.
		nh := setup(t)
		node, err := mesh.Join(context.Background(), svc, mesh.Config{
			DeviceKey: testDeviceKey(t),
			NetworkID: nh.netID,
			Addr:      mustAddr(fmt.Sprintf("10.42.%d.2", 100+i)),
			AgentPort: 8443,
		}, slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
		if err != nil {
			t.Fatalf("join network %d: %v", i, err)
		}
		nodes = append(nodes, node)
	}
	t.Cleanup(func() {
		for _, n := range nodes {
			_ = n.Close()
		}
	})

	g1, h1 := settle()

	perNetGoroutines := float64(g1-g0) / networks
	perNetHeapMB := (h1 - h0) / networks

	t.Logf("joined %d networks", networks)
	t.Logf("goroutines: %d -> %d  (%.1f per network)", g0, g1, perNetGoroutines)
	t.Logf("heap:       %.1f -> %.1f MB  (%.2f MB per network)", h0, h1, perNetHeapMB)
	t.Logf("extrapolated: 100 networks ~= %.0f goroutines, ~%.0f MB heap",
		perNetGoroutines*100, perNetHeapMB*100)

	// A sanity bound, not a benchmark. If a join ever starts costing hundreds of
	// goroutines the sharding guidance in design.md needs revisiting.
	if perNetGoroutines > 60 {
		t.Errorf("%.0f goroutines per joined network is higher than expected", perNetGoroutines)
	}
}
