package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/wire"
)

// A route reaches every other machine's configuration, and the gateway's
// certificate carries the prefix.
//
// Both halves matter and only together. The rendered unsafe_routes entry is
// what makes a peer send the packet; the certificate is what makes nebula on
// the gateway accept and forward it. Either alone is a route that silently
// does nothing.
func TestRouteReachesPeersAndTheCertificate(t *testing.T) {
	h := setupRoutable(t, "192.168.88.0/24")
	ts := h.serve(t, freeUDPPort(t))

	gw := h.createAndEnroll(t, ts, "lab-pi", "10.42.90.1", false, false, nil)

	var rt wire.RouteResponse
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+gw.id+"/routes",
		wire.CreateRouteRequest{Prefix: "192.168.88.0/24"}, &rt); code != http.StatusCreated {
		t.Fatalf("add route: status %d", code)
	}
	if rt.GatewayAddr != "10.42.90.1" {
		t.Errorf("gateway addr = %q, want the membership's overlay address", rt.GatewayAddr)
	}

	// A peer enrolled AFTER the route exists must be told about it.
	peer := h.createAndEnroll(t, ts, "consumer", "10.42.90.9", false, false, nil)
	cfg := readFile(t, paths.DefaultLayout(peer.dir).ConfigPath())

	if !strings.Contains(cfg, "unsafe_routes") {
		t.Fatalf("the peer was not told about the route:\n%s", cfg)
	}
	if !strings.Contains(cfg, "192.168.88.0/24") || !strings.Contains(cfg, "10.42.90.1") {
		t.Errorf("the route names the wrong prefix or gateway:\n%s", cfg)
	}

	// The GATEWAY must not route to itself. An unsafe_route naming its own
	// address as the via is a loop.
	gwCfg := readFile(t, paths.DefaultLayout(gw.dir).ConfigPath())
	if strings.Contains(gwCfg, "unsafe_routes") {
		t.Errorf("the gateway was given a route to its own prefix:\n%s", gwCfg)
	}
}

// Two gateways for one prefix render as ONE entry with two `via` gateways.
//
// That is what makes nebula load balance and fail between them. Two separate
// entries would be accepted and treated as a single path, losing exactly the
// redundancy the second gateway was added for — and it would look correct.
func TestTwoGatewaysForOnePrefixRenderAsOneEntry(t *testing.T) {
	h := setupRoutable(t, "192.168.88.0/24")
	ts := h.serve(t, freeUDPPort(t))

	a := h.createAndEnroll(t, ts, "pi-a", "10.42.91.1", false, false, nil)
	b := h.createAndEnroll(t, ts, "pi-b", "10.42.91.2", false, false, nil)

	for _, g := range []struct {
		id     string
		weight int
	}{{a.id, 10}, {b.id, 5}} {
		if code := h.adminPost(t, ts.URL+"/v1/memberships/"+g.id+"/routes",
			wire.CreateRouteRequest{Prefix: "192.168.88.0/24", Weight: g.weight},
			nil); code != http.StatusCreated {
			t.Fatalf("add route: status %d", code)
		}
	}

	peer := h.createAndEnroll(t, ts, "consumer", "10.42.91.9", false, false, nil)
	cfg := readFile(t, paths.DefaultLayout(peer.dir).ConfigPath())

	if n := strings.Count(cfg, "- route: 192.168.88.0/24"); n != 1 {
		t.Fatalf("the prefix rendered %d times; two gateways must be one entry:\n%s", n, cfg)
	}
	for _, want := range []string{"10.42.91.1", "10.42.91.2", "weight: 10", "weight: 5"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("the rendered route is missing %q:\n%s", want, cfg)
		}
	}
}

// A prefix the CA does not permit is refused at issuance, not rendered.
//
// The certificate is the authority. A route stored for a prefix outside the
// CA's constraint must fail loudly at enrollment rather than producing a
// configuration that reaches nobody — which is the failure that would take a
// day to attribute.
func TestARouteOutsideTheCAIsRefused(t *testing.T) {
	h := setupRoutable(t, "192.168.88.0/24")
	ts := h.serve(t, freeUDPPort(t))

	gw := h.createAndEnroll(t, ts, "over-reach", "10.42.92.1", false, false, nil)

	// 10.99.0.0/16 is outside what the CA was created to permit.
	if code := h.adminPost(t, ts.URL+"/v1/memberships/"+gw.id+"/routes",
		wire.CreateRouteRequest{Prefix: "10.99.0.0/16"}, nil); code != http.StatusCreated {
		t.Fatalf("add route: status %d", code)
	}

	// Enrolment now has to mint a certificate carrying it, and cannot.
	var codeResp wire.EnrollmentCodeResponse
	h.adminPost(t, ts.URL+"/v1/memberships/"+gw.id+"/enrollment-code", nil, &codeResp)

	kp, err := agent.GenerateKeypair(h.curve)
	if err != nil {
		t.Fatal(err)
	}
	_, err = agent.NewClient(ts.URL).Enroll(t.Context(), h.deviceFor(t, gw.id), codeResp.Code, kp, "e2e")
	if err == nil {
		t.Fatal("a certificate was issued for a prefix the CA does not permit")
	}
}
