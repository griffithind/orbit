package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/mesh"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/wire"
)

// The phase-5 property: the agent API is not merely authenticated, it is
// unroutable from outside the mesh.
//
// A bearer token on every managed host is a credential an attacker can steal
// and replay from anywhere. Binding the agent API to an overlay listener
// removes that entire class: there is no token, and there is no network path to
// the endpoint without a valid certificate for that network.

// servePublicOnly mounts only the enroll and admin surfaces, exactly as orbitd
// does for its public listener.
func (h *harness) servePublicOnly(t *testing.T, nebulaPort int) *httptest.Server {
	t.Helper()

	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      nebulaPort,
	})
	srv := api.New(h.store, svc, api.Config{
		SignerFactory:       h.vault.SignerFactory(),
		SealNetworkIdentity: h.sealNetworkIdentity,
		SealCAKey:           h.sealCAKey,
		DisableEnrollLimit:  true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mux := http.NewServeMux()
	srv.EnrollRoutes(mux)
	srv.AdminRoutes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// TestAgentAPIAbsentFromPublicListener is the security assertion.
//
// Not "returns 401" — absent. A 401 would mean the route exists and only
// authentication stands between the internet and it; 404 means there is nothing
// there to attack.
func TestAgentAPIAbsentFromPublicListener(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	for _, path := range []string{
		"/agent/v1/state",
		"/agent/v1/watch",
		"/agent/v1/report",
		"/agent/v1/renew",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s on the public listener = %d, want 404 (route must not exist there)",
				path, resp.StatusCode)
		}
	}

	// Enrollment must still work there; that is the whole point of the split.
	resp, err := http.Post(ts.URL+"/enroll/v1/enroll", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Error("enroll endpoint is missing from the public listener")
	}
}

// TestControlPlaneJoinsOverlay exercises mesh.Join: the control plane issues
// itself a certificate, brings up a userspace nebula stack, and serves the
// agent API on an address only mesh members can reach.
//
// This is orbitd's real startup path, not a stand-in.
func TestControlPlaneJoinsOverlay(t *testing.T) {
	h := setup(t)

	// A lighthouse so the control plane and the agent can find each other.
	lhPort := freeUDPPort(t)
	lhServer := h.serve(t, lhPort)
	lh := h.createAndEnroll(t, lhServer, "lh-overlay", "10.42.6.1", true, true,
		[]string{fmt.Sprintf("127.0.0.1:%d", lhPort)})
	lhNode, err := bootNebula(t, lh.dir, lh.addr)
	if err != nil {
		t.Fatalf("boot lighthouse: %v", err)
	}
	_ = lhNode

	// The control plane joins the overlay on its own address, serving the agent
	// API on agentPort and accepting nothing else inbound.
	const agentPort = 8446
	cpPort := freeUDPPort(t)
	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	cpSvc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      cpPort,
	})

	node, err := mesh.Join(context.Background(), cpSvc, mesh.Config{
		DeviceKey:  testDeviceKey(t),
		NetworkID:  h.netID,
		Addr:       mustAddr("10.42.6.2"),
		ListenPort: cpPort,
		AgentPort:  agentPort,
	}, meshLogger(t))
	if err != nil {
		t.Fatalf("control plane could not join the overlay: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })

	if node.NetworkID() != h.netID {
		t.Errorf("node serves network %s, want %s", node.NetworkID(), h.netID)
	}
	if node.NotAfter.Before(time.Now()) {
		t.Error("control plane issued itself an already-expired certificate")
	}

	ln, err := node.Listen(agentPort)
	if err != nil {
		t.Fatalf("overlay listen: %v", err)
	}
	mux := http.NewServeMux()
	api.New(h.store, cpSvc, api.Config{
		Agent: &api.AgentListener{NetworkID: node.NetworkID()},
	}, slog.New(slog.NewTextHandler(io.Discard, nil))).AgentRoutes(mux)

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// An enrolled host reaches it over the tunnel, with no credential.
	clientPort := freeUDPPort(t)
	clientServer := h.serve(t, clientPort)
	client := h.createAndEnroll(t, clientServer, "overlay-client", "10.42.6.7", false, false, nil)
	clientNode, err := bootNebula(t, client.dir, client.addr)
	if err != nil {
		t.Fatalf("boot client: %v", err)
	}

	st, err := agent.ReadState(client.dir)
	if err != nil {
		t.Fatal(err)
	}
	ac := agent.NewClient(node.AgentEndpoint(agentPort))
	ac.HTTP = overlayHTTPClient(clientNode)

	// Retry while the tunnel to the control plane establishes.
	var state *wire.StateResponse
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		state, err = ac.State(context.Background(), st.ConfigEpoch, st.BlocklistEpoch)
		if err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("agent could not reach the control plane over the overlay: %v", err)
	}
	if state.ConfigEpoch == 0 {
		t.Error("overlay state response is empty")
	}

	t.Logf("agent reached the control plane at %s with no credential; "+
		"identity came from its verified overlay source address",
		node.AgentEndpoint(agentPort))

	// And renewal works over the same path.
	kp, err := agent.GenerateKeypair(cert.Curve_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := ac.Renew(context.Background(), kp)
	if err != nil {
		t.Fatalf("renew over the overlay: %v", err)
	}
	if renewed.Certificate == "" {
		t.Error("renewal over the overlay returned no certificate")
	}
}

// TestEnrollmentAdvertisesLiveReplicas proves an agent learns where to go next,
// and that the list reflects the live registry rather than configuration.
// Without it the host keeps using the public URL forever and the overlay
// listeners are decorative.
func TestEnrollmentAdvertisesLiveReplicas(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      freeUDPPort(t),
	})

	srv := api.New(h.store, svc, api.Config{DisableEnrollLimit: true},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	srv.EnrollRoutes(mux)
	srv.AdminRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// Register two replicas directly, standing in for two orbitd instances
	// having announced themselves.
	mkHost := func(name, addr string) uuid.UUID {
		var hr wire.MembershipResponse
		if code := h.createHost(t, ts.URL, membershipSpec{
			NetworkID: h.netID.String(), Name: name, OverlayAddr: addr,
		}, &hr); code != http.StatusCreated {
			t.Fatalf("create %s: %d", name, code)
		}
		return uuid.MustParse(hr.ID)
	}
	cp1 := mkHost("cp-1", "10.42.0.2")
	cp2 := mkHost("cp-2", "10.42.0.3")

	for _, cp := range []struct {
		id   uuid.UUID
		addr string
	}{{cp1, "10.42.0.2"}, {cp2, "10.42.0.3"}} {
		if err := h.store.Register(ctx, h.netID, cp.id, mustAddr(cp.addr), 8443); err != nil {
			t.Fatalf("register replica: %v", err)
		}
	}

	var host wire.MembershipResponse
	if code := h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "learns-endpoints", OverlayAddr: "10.42.5.5",
		RoleID: h.roleID.String(),
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host: %d", code)
	}
	var code wire.EnrollmentCodeResponse
	h.adminPost(t, ts.URL+"/v1/memberships/"+host.ID+"/enrollment-code", nil, &code)

	kp, _ := agent.GenerateKeypair(cert.Curve_CURVE25519)
	resp, err := agent.NewClient(ts.URL).Enroll(ctx, code.Code, kp, "e2e")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if len(resp.AgentEndpoints) != 2 {
		t.Fatalf("agent_endpoints = %v, want both replicas", resp.AgentEndpoints)
	}

	// Failover rotates; it must not get stuck on one replica.
	st := agent.State{BaseURL: ts.URL}
	st.SetAgentURLs(resp.AgentEndpoints)
	first := st.ControlURL()
	second := st.NextControlURL()
	if first == second {
		t.Errorf("failover did not rotate: %q then %q", first, second)
	}
	if third := st.NextControlURL(); third != first {
		t.Errorf("rotation is not cyclic: expected to return to %q, got %q", first, third)
	}

	// A refreshed list must keep the agent on the replica it is already using,
	// or any membership change herds the whole fleet onto index 0.
	st.Preferred = 1
	using := st.ControlURL()
	st.SetAgentURLs([]string{"http://10.42.0.9:8443", using})
	if st.ControlURL() != using {
		t.Errorf("refreshing the replica list moved the agent off %q to %q", using, st.ControlURL())
	}
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func meshLogger(t *testing.T) *slog.Logger {
	if os.Getenv("ORBIT_DEBUG_MESH") != "" {
		return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
