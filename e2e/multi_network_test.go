package e2e

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/mesh"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/wire"
)

// One process, two networks, two UDP ports.
//
// This is what `orbitd serve -mesh a=… -mesh b=…:4243` builds, and it did not
// work: ListenPort was assigned inside the loop over meshes, so every network
// got the same port and the second failed with "address already in use" from
// inside nebula. -nebula-port defaults to 4242, so EVERY multi-network control
// plane failed at startup.
//
// Nebula cannot share a port between networks — its v1 header carries no
// network identifier, so a received packet cannot be attributed to one — which
// makes a port per network the only shape available, not a preference.
func TestTwoNetworksInOneProcess(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	secondID := h.secondNetwork(t, ts, "10.91.0.0/24")

	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })
	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(), ListenPort: freeUDPPort(t),
	})

	// One device key. One process is one machine, however many networks it
	// joins — the same rule orbitd follows.
	key := testDeviceKey(t)
	portA, portB := freeUDPPort(t), freeUDPPort(t)

	nodeA, err := mesh.Join(context.Background(), svc, mesh.Config{
		DeviceKey: key, NetworkID: h.netID, Addr: mustAddr("10.42.90.1"),
		AgentPort: 8461, ListenPort: portA,
	}, log)
	if err != nil {
		t.Fatalf("first network: %v", err)
	}
	t.Cleanup(func() { _ = nodeA.Close() })

	nodeB, err := mesh.Join(context.Background(), svc, mesh.Config{
		DeviceKey: key, NetworkID: secondID, Addr: mustAddr("10.91.0.1"),
		// The SAME agent port on purpose. It is not a host port: each node
		// listens on its own network's gvisor netstack, so two overlays using
		// 8461 are two independent listeners. Only ListenPort is a real host
		// UDP socket, and that is why only it has to differ.
		AgentPort: 8461, ListenPort: portB,
	}, log)
	if err != nil {
		t.Fatalf("second network on its own port %d (first was %d): %v", portB, portA, err)
	}
	t.Cleanup(func() { _ = nodeB.Close() })

	if nodeA.MembershipID() == nodeB.MembershipID() {
		t.Error("both networks resolved to one membership; they are separate networks")
	}
}

// secondNetwork creates a network with an active CA, ready to be joined.
func (h *harness) secondNetwork(t *testing.T, ts *httptest.Server, cidr string) uuid.UUID {
	t.Helper()

	var net wire.NetworkResponse
	if s := h.adminPost(t, ts.URL+"/v1/networks", wire.CreateNetworkRequest{
		Name: "second-" + uuid.NewString()[:8], CIDRs: []string{cidr},
	}, &net); s != http.StatusCreated {
		t.Fatalf("create the second network: status %d", s)
	}

	// A network with no active CA cannot issue, so joining it fails long before
	// any port is bound — which would make this test pass for the wrong reason.
	var caResp wire.CAResponse
	if s := h.adminPost(t, ts.URL+"/v1/cas", wire.CreateCARequest{
		NetworkID: net.ID, Name: "second-ca",
		Networks: []string{cidr}, Groups: []string{"default"}, Days: 30,
	}, &caResp); s != http.StatusCreated {
		t.Fatalf("create a CA for the second network: status %d", s)
	}
	if s := h.adminPost(t, ts.URL+"/v1/cas/"+caResp.ID+"/activate",
		wire.ActivateCARequest{AcknowledgeCutoff: true}, nil); s != http.StatusOK {
		t.Fatalf("activate the second network's CA: status %d", s)
	}

	id, err := uuid.Parse(net.ID)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
