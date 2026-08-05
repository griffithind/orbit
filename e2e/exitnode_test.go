package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/wire"
)

// A default route reaches ONLY the machine that asked for it.
//
// This is the property that separates an exit node from an ordinary route, and
// the one that fails expensively. Rendering every 0.0.0.0/0 to everybody would
// move a whole fleet's internet traffic through whichever gateway was added
// most recently — a change nobody made, showing up a week later as a latency
// complaint nobody can attribute.
func TestAnExitNodeReachesOnlyTheMachineThatChoseIt(t *testing.T) {
	h := setupRoutable(t, "0.0.0.0/0")
	ts := h.serve(t, freeUDPPort(t))

	gw := h.createAndEnroll(t, ts, "exit-gw", "10.42.95.1", false, false, nil)

	var rt wire.RouteResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+gw.id+"/routes",
		wire.CreateRouteRequest{Prefix: "0.0.0.0/0", Masquerade: true},
		&rt); code != http.StatusCreated {
		t.Fatalf("add exit route: status %d", code)
	}

	// A machine that has NOT chosen it must not receive it.
	bystander := h.createAndEnroll(t, ts, "bystander", "10.42.95.8", false, false, nil)
	cfg := readFile(t, agent.DefaultLayout(bystander.dir).ConfigPath())
	if strings.Contains(cfg, "0.0.0.0/0") {
		t.Fatalf("a machine that chose no exit node was given a default route:\n%s", cfg)
	}
	if strings.Contains(cfg, "so_mark") {
		t.Error("so_mark was emitted for a host with no default route")
	}

	// One that chooses it does.
	user := h.createAndEnroll(t, ts, "user", "10.42.95.9", false, false, nil)
	if code := h.adminReq(t, http.MethodPut,
		ts.URL+"/v1/memberships/"+user.id+"/exit-node",
		wire.SetExitNodeRequest{RouteID: rt.ID}, nil); code != http.StatusNoContent {
		t.Fatalf("choose exit node: status %d", code)
	}

	mat := h.rerender(t, ts, user)
	if !strings.Contains(mat.Config, "0.0.0.0/0") {
		t.Fatalf("the machine that chose an exit node was not given it:\n%s", mat.Config)
	}
	// so_mark is what stops nebula's own UDP being routed into the tunnel it
	// carries. Without it a default route is a loop.
	if !strings.Contains(mat.Config, "so_mark") {
		t.Errorf("so_mark missing; a default route without it is a routing loop:\n%s", mat.Config)
	}
}

// The gateway is told to forward and to NAT, in the same signed document.
//
// Nebula does neither. Without the instruction the gateway drops every
// forwarded packet, and the failure is a silent one — the tunnel is up, the
// route is present, and nothing arrives.
func TestAGatewayIsToldToForwardAndNAT(t *testing.T) {
	h := setupRoutable(t, "0.0.0.0/0", "192.168.88.0/24")
	ts := h.serve(t, freeUDPPort(t))

	gw := h.createAndEnroll(t, ts, "dual-gw", "10.42.96.1", false, false, nil)

	// NAT for the internet, none for the LAN — the case that makes masquerade a
	// per-route flag rather than a host setting.
	for _, r := range []wire.CreateRouteRequest{
		{Prefix: "0.0.0.0/0", Masquerade: true},
		{Prefix: "192.168.88.0/24", Masquerade: false},
	} {
		if code := h.adminPost(t, ts.URL+"/v1/memberships/"+gw.id+"/routes", r, nil); code != http.StatusCreated {
			t.Fatalf("add %s: status %d", r.Prefix, code)
		}
	}

	mat := h.rerender(t, ts, gw)
	state, err := agent.HostStateFromConfig(mat.Config)
	if err != nil {
		t.Fatalf("read host state: %v", err)
	}
	if !state.Forward {
		t.Error("a gateway was not told to enable forwarding")
	}
	if len(state.Masquerade) != 1 || state.Masquerade[0].String() != "0.0.0.0/0" {
		t.Errorf("masquerade = %v, want only 0.0.0.0/0 — the LAN route asked for none",
			state.Masquerade)
	}

	// And an ordinary machine gets no instructions at all, so the feature
	// existing does not rewrite every configuration in a fleet.
	plain := h.createAndEnroll(t, ts, "plain", "10.42.96.9", false, false, nil)
	pcfg := readFile(t, agent.DefaultLayout(plain.dir).ConfigPath())
	if strings.Contains(pcfg, "orbit:") {
		t.Errorf("a non-gateway was given host-state instructions:\n%s", pcfg)
	}
	pstate, err := agent.HostStateFromConfig(pcfg)
	if err != nil {
		t.Fatal(err)
	}
	if !pstate.Empty() {
		t.Errorf("a non-gateway has host state: %s", pstate.String())
	}
}

// Choosing a route that is not a default route is refused.
//
// Otherwise a membership ends up with an "exit node" that is a LAN prefix, and
// the machine's internet keeps working while somebody believes it is tunnelled.
func TestOnlyADefaultRouteCanBeAnExitNode(t *testing.T) {
	h := setupRoutable(t, "192.168.88.0/24")
	ts := h.serve(t, freeUDPPort(t))

	gw := h.createAndEnroll(t, ts, "lan-gw", "10.42.97.1", false, false, nil)
	var rt wire.RouteResponse
	h.adminPost(t, ts.URL+"/v1/memberships/"+gw.id+"/routes",
		wire.CreateRouteRequest{Prefix: "192.168.88.0/24"}, &rt)

	user := h.createAndEnroll(t, ts, "user", "10.42.97.9", false, false, nil)
	var errResp wire.Error
	code := h.adminReq(t, http.MethodPut,
		ts.URL+"/v1/memberships/"+user.id+"/exit-node",
		wire.SetExitNodeRequest{RouteID: rt.ID}, &errResp)
	if code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", code)
	}
	if !strings.Contains(errResp.Error, "not a default route") {
		t.Errorf("the error does not say what is wrong: %q", errResp.Error)
	}
}
