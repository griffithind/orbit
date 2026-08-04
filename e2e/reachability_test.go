package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// `orbit why <src> <dst>` — the bidirectional answer.
//
// A host knows its own rules and cannot read its peer's, so the node-local
// command is necessarily one direction of two. The control plane holds both
// compiled rulesets, and nebula enforces outbound on the sender and inbound on
// the receiver — so a flow passes only if both agree, and that conjunction is
// the thing no machine can compute for itself.

// policyHosts puts the network on the policy document, stores doc, and returns
// two hosts to ask about.
func (h *harness) policyHosts(t *testing.T, ts *httptest.Server, doc, srcName, srcAddr, dstName, dstAddr string) (src, dst wire.HostResponse) {
	t.Helper()
	src = h.createTaggedHost(t, ts.URL, srcName, srcAddr, nil)
	dst = h.createTaggedHost(t, ts.URL, dstName, dstAddr, nil)

	// Document first, then the switch. The server refuses the other order —
	// nebula's firewall is default-deny, so switching a network with no stored
	// document would render an empty rule set on every host and drop all
	// traffic — and that refusal is worth going through rather than around.
	if code, body := h.putPolicy(t, ts.URL, doc); code != http.StatusOK {
		t.Fatalf("store policy: %d (%+v)", code, body)
	}

	// Acknowledged because the switch replaces the firewall on every host in
	// the network, which is exactly what these tests want it to do.
	var updated wire.NetworkUpdateResponse
	if code := h.adminReq(t, http.MethodPatch, ts.URL+"/v1/networks/"+h.netName,
		wire.UpdateNetworkRequest{
			FirewallSource:            ptr(store.FirewallSourcePolicy),
			AcknowledgeFirewallChange: true,
		}, &updated); code != http.StatusOK {
		t.Fatalf("switch to policy firewall: %d", code)
	}
	return src, dst
}

// enrollIntoDirForHost enrolls a host that already exists into a chosen
// directory, through the CLI.
//
// enrollIntoDir creates the host as well, and enrollExisting writes to a
// directory of its own choosing; this test needs an existing host in a
// directory an agent will later be pointed at.
func (h *harness) enrollIntoDirForHost(t *testing.T, ts *httptest.Server, hostID, dir string) {
	t.Helper()
	var code wire.EnrollmentCodeResponse
	if c := h.adminPost(t, ts.URL+"/v1/hosts/"+hostID+"/enrollment-code", nil, &code); c != http.StatusCreated {
		t.Fatalf("mint code for %s: %d", hostID, c)
	}
	res := h.cli(t, ts, "agent", "enroll", "-url", ts.URL, "-code", code.Code, "-dir", dir)
	if res.code != 0 {
		t.Fatalf("enroll %s: exit %d\n%s", hostID, res.code, res.stderr)
	}
}

// reachability asks the control plane.
func (h *harness) reachability(t *testing.T, ts *httptest.Server, src, dst, proto, port string) wire.ReachabilityResponse {
	t.Helper()
	code, body := h.rawGet(t, ts.URL+"/v1/networks/"+h.netName+
		"/reachability?src="+src+"&dst="+dst+"&proto="+proto+"&port="+port)
	if code != http.StatusOK {
		t.Fatalf("reachability %s→%s: %d (%s)", src, dst, code, body)
	}
	var out wire.ReachabilityResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return out
}

func TestReachabilityAnswersBothDirections(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	src, dst := h.policyHosts(t, ts, `{
  "version": 1,
  "allow": [
    {"src": ["host:why-src"], "dst": ["host:why-dst"], "proto": "tcp", "ports": ["5432"]}
  ]
}`, "why-src", "10.42.94.7", "why-dst", "10.42.94.8")

	ok := h.reachability(t, ts, src.Name, dst.Name, "tcp", "5432")
	if !ok.Allowed {
		t.Errorf("the flow the policy permits was reported denied: outbound=%v inbound=%v",
			ok.Outbound.Allowed, ok.Inbound.Allowed)
	}
	// Both halves must be evaluated, because which END denies a flow is what
	// decides whose policy an operator changes.
	if !ok.Outbound.Allowed || !ok.Inbound.Allowed {
		t.Errorf("one direction was not evaluated: outbound=%v inbound=%v",
			ok.Outbound.Allowed, ok.Inbound.Allowed)
	}

	if no := h.reachability(t, ts, src.Name, dst.Name, "tcp", "22"); no.Allowed {
		t.Error("tcp/22 is in no allowance and was reported allowed")
	}

	// The REVERSE pair, which the policy does not permit. An allowance is
	// directional, and a command reporting it symmetric would be telling an
	// operator their policy says something it does not.
	if rev := h.reachability(t, ts, dst.Name, src.Name, "tcp", "5432"); rev.Allowed {
		t.Error("the reverse direction was reported allowed; the allowance names " +
			"why-src as src, and it is not symmetric")
	}
}

// TestReachabilityAgreesWithTheHostsOwnAnswer is the property that makes two
// commands safe to ship.
//
// The control plane compiles from the stored policy; the agent matches against
// the configuration on its own disk. Both go through internal/fwmatch, and if
// they disagreed an operator would be told one thing by the server and the
// opposite by the machine — worse than either command not existing.
func TestReachabilityAgreesWithTheHostsOwnAnswer(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	src, _ := h.policyHosts(t, ts, `{
  "version": 1,
  "allow": [
    {"src": ["host:agree-src"], "dst": ["host:agree-dst"], "proto": "tcp", "ports": ["443", "8080"]}
  ]
}`, "agree-src", "10.42.95.7", "agree-dst", "10.42.95.8")

	// The source runs a real agent, so the rules it matches against are the
	// ones the control plane rendered rather than any the test wrote.
	root := shortTempDir(t)
	h.enrollIntoDirForHost(t, ts, src.ID, filepath.Join(root, "prod"))
	h.startAgent(t, root)

	for _, tc := range []struct{ proto, port string }{
		{"tcp", "443"}, {"tcp", "8080"}, {"tcp", "22"}, {"udp", "443"},
	} {
		server := h.reachability(t, ts, "agree-src", "agree-dst", tc.proto, tc.port)

		res := h.cliEnv(t, nil, "why", "10.42.95.8", "-root", root,
			"-proto", tc.proto, "-port", tc.port, "-json")
		if res.code != 0 {
			t.Fatalf("local why exited %d\n%s", res.code, res.stderr)
		}
		var local struct {
			Outbound struct {
				Allowed bool `json:"allowed"`
			} `json:"outbound"`
		}
		if err := json.Unmarshal([]byte(res.stdout), &local); err != nil {
			t.Fatalf("parse local explanation: %v\n%s", err, res.stdout)
		}

		// Only the OUTBOUND half is comparable: that is src's own table, which
		// both ends can see. The server's inbound half is dst's table, and src
		// has no access to it at all.
		if server.Outbound.Allowed != local.Outbound.Allowed {
			t.Errorf("%s/%s: the control plane says outbound allowed=%v and the host says %v.\n"+
				"An operator would be told opposite things by the two commands.",
				tc.proto, tc.port, server.Outbound.Allowed, local.Outbound.Allowed)
		}
	}
}

// TestReachabilityOnARoleNetworkSaysThereIsNoPolicy.
//
// A network still on per-role rules has no document to compile. Reporting an
// empty ruleset would render as a denial and send an operator to edit a policy
// that is not in force.
func TestReachabilityOnARoleNetworkSaysThereIsNoPolicy(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	src := h.createTaggedHost(t, ts.URL, "role-src", "10.42.96.7", nil)
	dst := h.createTaggedHost(t, ts.URL, "role-dst", "10.42.96.8", nil)

	got := h.reachability(t, ts, src.Name, dst.Name, "tcp", "443")
	if got.Note == "" {
		t.Fatal("a network with no policy document answered without saying so")
	}
	if !strings.Contains(got.Note, "role") {
		t.Errorf("the note does not point at where the rules actually come from: %q", got.Note)
	}
	if got.Allowed {
		t.Error("reported allowed on a network whose policy was never compiled")
	}
}

// TestReachabilityRejectsAnUnknownHost. A mistyped name is a mistake in the
// command, not a denial — reporting it as one would have an operator editing
// policy over a typo.
func TestReachabilityRejectsAnUnknownHost(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	src := h.createTaggedHost(t, ts.URL, "known", "10.42.97.7", nil)

	code, body := h.rawGet(t, ts.URL+"/v1/networks/"+h.netName+
		"/reachability?src="+src.Name+"&dst=nope")
	if code != http.StatusNotFound {
		t.Errorf("status %d, want 404\n%s", code, body)
	}
	if !strings.Contains(body, "nope") {
		t.Errorf("the error does not name the host asked for:\n%s", body)
	}

	// A missing operand is a different mistake and gets a different code.
	code, _ = h.rawGet(t, ts.URL+"/v1/networks/"+h.netName+"/reachability?src="+src.Name)
	if code != http.StatusBadRequest {
		t.Errorf("omitting dst gave %d, want 400", code)
	}
}
