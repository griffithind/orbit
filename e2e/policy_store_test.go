package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/policy"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The network policy document, through the store and through the API.
//
// Four properties, and each of them is one somebody could plausibly break while
// believing they were tidying up:
//
//   - A document round-trips. What is stored parses back to the document that was
//     sent, and version numbers count up per network.
//   - An invalid document is refused by BOTH check and apply, with the fault
//     named. A check endpoint that is more permissive than the write it rehearses
//     is worse than no check endpoint.
//   - A no-op PUT does not bump the config epoch. The comparison is semantic —
//     jsonb, in Postgres — so a re-send with different key order and whitespace
//     is correctly nothing, and a reconcile loop is free rather than fleet-wide
//     work.
//   - A real edit does bump it, or the document reaches no host and takes effect
//     nowhere.
//
// Plus the opt-in switch, which is the one that decides whether any of the above
// matters: a stored document that is not switched on must be rendered by nothing.

// A small but real document: SSH from everywhere, and one tier-to-tier rule.
const policyDocV1 = `{
	"version": 1,
	"allow": [
		{"src": ["*"], "dst": ["*"], "proto": "tcp", "ports": ["22"], "note": "ssh"},
		{"src": ["tag:web"], "dst": ["tag:db"], "proto": "tcp", "ports": ["5432"]}
	]
}`

// The same document, reformatted and with keys reordered. jsonb compares
// semantically, so this must be recognised as no change at all.
const policyDocV1Reordered = `{
	"allow": [
		{ "note": "ssh", "ports": ["22"], "proto": "tcp", "dst": ["*"], "src": ["*"] },
		{
			"ports":  [ "5432" ],
			"proto":  "tcp",
			"dst":    [ "tag:db" ],
			"src":    [ "tag:web" ]
		}
	],
	"version": 1
}`

const policyDocV2 = `{
	"version": 1,
	"allow": [
		{"src": ["*"], "dst": ["*"], "proto": "tcp", "ports": ["22"], "note": "ssh"},
		{"src": ["tag:web"], "dst": ["tag:db"], "proto": "tcp", "ports": ["5432"]},
		{"src": ["*"], "dst": ["*"], "proto": "icmp", "note": "ping, for debugging"}
	]
}`

func (h *harness) policyURL(ts string) string {
	return ts + "/v1/networks/" + h.netID.String() + "/policy"
}

// putPolicy PUTs a raw document and returns the status and decoded body.
//
// A raw body rather than a marshalled struct, because that is the contract: the
// request body IS the document, so `curl --data-binary @policy.json` and this
// test send the same bytes.
func (h *harness) putPolicy(t *testing.T, ts, doc string) (int, wire.PolicyUpdateResponse) {
	t.Helper()
	code, body := h.adminRawBody(t, http.MethodPut, h.policyURL(ts), doc)
	var out wire.PolicyUpdateResponse
	if code < 300 {
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode policy response: %v (%s)", err, body)
		}
	}
	return code, out
}

// adminRawBody sends a body verbatim.
//
// Not adminRaw, which json.Marshals what it is given: the policy endpoints take
// the document as the WHOLE body with no envelope, and — more to the point — one
// of the cases below is a body that is not valid JSON at all. A helper that
// marshals cannot express that, and "the server rejects malformed JSON" is
// exactly the kind of thing that is assumed rather than tested until a proxy
// truncates a request.
func (h *harness) adminRawBody(t *testing.T, method, url, body string) (int, string) {
	t.Helper()

	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// TestPolicyRoundTripsAndVersions is the storage contract.
func TestPolicyRoundTripsAndVersions(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	// Nothing yet, and the refusal has to say which of the two things is wrong.
	// "network not found" on a network that plainly exists is the message that
	// sends an operator looking for a problem they do not have.
	code, body := h.adminRaw(t, http.MethodGet, h.policyURL(ts.URL), nil)
	if code != http.StatusNotFound {
		t.Fatalf("GET policy on a network with none: %d, want 404 (%s)", code, body)
	}
	if !strings.Contains(body, "no policy document") {
		t.Errorf("404 body does not say the network has no document: %s", body)
	}

	code, first := h.putPolicy(t, ts.URL, policyDocV1)
	if code != http.StatusOK {
		t.Fatalf("PUT first policy: %d", code)
	}
	if !first.Changed {
		t.Error("the first document a network ever had reported changed=false")
	}
	if first.Version != 1 {
		t.Errorf("first version is %d, want 1", first.Version)
	}
	if first.PreviousVersion != 0 {
		t.Errorf("previous_version is %d on a network's first document, want 0", first.PreviousVersion)
	}

	// Round-trip. NOT byte-identical — the document is stored as jsonb, so key
	// order and whitespace are normalized away, and that normalization is exactly
	// what makes the no-op case below provable. What must survive is the
	// MEANING, so the comparison is between parsed documents.
	sent, err := policy.Parse([]byte(policyDocV1))
	if err != nil {
		t.Fatalf("the test's own document does not parse: %v", err)
	}
	got, err := policy.Parse(first.Document)
	if err != nil {
		t.Fatalf("stored document does not parse back: %v (%s)", err, first.Document)
	}
	if !documentsEqual(sent, got) {
		t.Errorf("document did not round-trip.\n sent: %+v\nstored: %+v", sent, got)
	}

	// And through the read endpoint, which is a different query.
	var read wire.PolicyResponse
	if code := h.adminReq(t, http.MethodGet, h.policyURL(ts.URL), nil, &read); code != http.StatusOK {
		t.Fatalf("GET policy: %d", code)
	}
	if read.Version != 1 {
		t.Errorf("GET reports version %d, want 1", read.Version)
	}
	reread, err := policy.Parse(read.Document)
	if err != nil {
		t.Fatalf("document from GET does not parse: %v", err)
	}
	if !documentsEqual(sent, reread) {
		t.Errorf("GET returned a different document than PUT stored")
	}
	if read.FirewallSource != store.FirewallSourceRole {
		t.Errorf("a network that never opted in reports firewall_source %q, want %q",
			read.FirewallSource, store.FirewallSourceRole)
	}
}

// TestPolicyNoOpDoesNotBumpEpoch is the property the whole jsonb decision exists
// for.
//
// A config epoch bump wakes every agent in the network to fetch and re-render. A
// reconcile loop re-applying the same desired state every few minutes must
// therefore be free, or the safest thing an operator can do becomes the most
// expensive thing the fleet does.
func TestPolicyNoOpDoesNotBumpEpoch(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	if code, _ := h.putPolicy(t, ts.URL, policyDocV1); code != http.StatusOK {
		t.Fatalf("PUT first policy: %d", code)
	}
	before := h.networkEpochs(t, ts.URL).ConfigEpoch

	// The same document, reformatted and with every key reordered.
	code, noop := h.putPolicy(t, ts.URL, policyDocV1Reordered)
	if code != http.StatusOK {
		t.Fatalf("PUT reordered policy: %d", code)
	}
	if noop.Changed {
		t.Error("a re-send with different key order and whitespace reported changed=true; " +
			"the comparison is supposed to be jsonb, not bytes")
	}
	if noop.Version != 1 {
		t.Errorf("a no-op PUT wrote version %d; it must write no version at all", noop.Version)
	}

	after := h.networkEpochs(t, ts.URL).ConfigEpoch
	if after != before {
		t.Fatalf("config epoch %d -> %d on a no-op PUT: every agent in the network was "+
			"woken to re-render a document identical to the one it is already running",
			before, after)
	}

	// A real edit, and now it must move.
	code, edited := h.putPolicy(t, ts.URL, policyDocV2)
	if code != http.StatusOK {
		t.Fatalf("PUT edited policy: %d", code)
	}
	if !edited.Changed {
		t.Fatal("a document with an added rule reported changed=false")
	}
	if edited.Version != 2 || edited.PreviousVersion != 1 {
		t.Errorf("edit reports version %d (was %d), want 2 (was 1)",
			edited.Version, edited.PreviousVersion)
	}

	afterEdit := h.networkEpochs(t, ts.URL).ConfigEpoch
	if afterEdit <= after {
		t.Fatalf("config epoch %d -> %d on a real edit: a policy change no host is told "+
			"about is a firewall change that never takes effect", after, afterEdit)
	}
	if edited.ConfigEpoch != afterEdit {
		t.Errorf("response reports config epoch %d, network is at %d; the version row "+
			"records the epoch it produced and the two must agree",
			edited.ConfigEpoch, afterEdit)
	}
}

// TestInvalidPolicyRefusedByBothCheckAndApply.
//
// Both, and with the same fault named, because a check endpoint that is more
// permissive than the write it rehearses is worse than none: it certifies a
// document that then fails, and the operator has already stopped looking.
func TestInvalidPolicyRefusedByBothCheckAndApply(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	checkURL := h.policyURL(ts.URL) + "/check"

	for _, tc := range []struct {
		name string
		doc  string
		// want is a fragment the refusal must contain. Asserted because "400" on
		// its own is not a usable answer for a fleet-wide document — the operator
		// has to be told which line is wrong.
		want string
	}{
		{
			name: "unknown top-level field",
			doc:  `{"version":1,"allows":[]}`,
			want: "allows",
		},
		{
			name: "unknown field inside an entry",
			doc:  `{"version":1,"allow":[{"src":["*"],"dst":["*"],"protocol":"tcp","ports":["22"]}]}`,
			want: "allow[0]",
		},
		{
			name: "missing version",
			doc:  `{"allow":[]}`,
			want: "version",
		},
		{
			name: "proto nebula cannot match",
			doc:  `{"version":1,"allow":[{"src":["*"],"dst":["*"],"proto":"sctp","ports":["22"]}]}`,
			want: "sctp",
		},
		{
			name: "icmp with ports, which nebula silently discards",
			doc:  `{"version":1,"allow":[{"src":["*"],"dst":["*"],"proto":"icmp","ports":["22"]}]}`,
			want: "icmp",
		},
		{
			name: "bare token is not a selector",
			doc:  `{"version":1,"allow":[{"src":["web"],"dst":["*"],"proto":"tcp","ports":["22"]}]}`,
			want: "web",
		},
		{
			name: "not JSON at all",
			doc:  `{"version":1,`,
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkCode, checkBody := h.adminRawBody(t, http.MethodPost, checkURL, tc.doc)
			if checkCode != http.StatusBadRequest {
				t.Errorf("check accepted an invalid document: %d (%s)", checkCode, checkBody)
			}
			applyCode, applyBody := h.adminRawBody(t, http.MethodPut, h.policyURL(ts.URL), tc.doc)
			if applyCode != http.StatusBadRequest {
				t.Errorf("apply accepted an invalid document: %d (%s)", applyCode, applyBody)
			}
			if tc.want == "" {
				return
			}
			if !strings.Contains(checkBody, tc.want) {
				t.Errorf("check refusal does not name %q: %s", tc.want, checkBody)
			}
			if !strings.Contains(applyBody, tc.want) {
				t.Errorf("apply refusal does not name %q: %s", tc.want, applyBody)
			}
		})
	}

	// Nothing was stored by any of that. A check endpoint that stored on the way
	// to refusing, or an apply whose validation ran after the write, would both
	// pass every assertion above.
	if code, _ := h.adminRaw(t, http.MethodGet, h.policyURL(ts.URL), nil); code != http.StatusNotFound {
		t.Errorf("a refused document was stored anyway: GET returned %d", code)
	}
}

// TestPolicyCheckStoresNothing pins the other half of the check contract: a
// VALID document must not be written either. The whole value of the endpoint is
// that it is safe to run against production from a CI job.
func TestPolicyCheckStoresNothing(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	code, body := h.adminRawBody(t, http.MethodPost, h.policyURL(ts.URL)+"/check", policyDocV1)
	if code != http.StatusOK {
		t.Fatalf("check a valid document: %d (%s)", code, body)
	}
	var res wire.PolicyCheckResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("decode check response: %v", err)
	}
	if !res.Valid {
		t.Error("a 200 from check reported valid=false")
	}
	if res.CurrentVersion != 0 {
		t.Errorf("current_version is %d on a network with no document, want 0", res.CurrentVersion)
	}
	if !res.WouldChange {
		t.Error("would_change is false against a network with no document at all")
	}

	if code, _ := h.adminRaw(t, http.MethodGet, h.policyURL(ts.URL), nil); code != http.StatusNotFound {
		t.Fatalf("check stored the document it was only supposed to validate: GET returned %d", code)
	}

	// And once something IS stored, would_change has to agree with what a PUT
	// would actually do — the two are the same jsonb comparison and must never
	// disagree.
	if code, _ := h.putPolicy(t, ts.URL, policyDocV1); code != http.StatusOK {
		t.Fatalf("PUT: %d", code)
	}
	code, body = h.adminRawBody(t, http.MethodPost, h.policyURL(ts.URL)+"/check", policyDocV1Reordered)
	if code != http.StatusOK {
		t.Fatalf("check reordered document: %d (%s)", code, body)
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("decode check response: %v", err)
	}
	if res.WouldChange {
		t.Error("check says a reordered but identical document would change something; " +
			"PUT says it would not, and the two run the same comparison")
	}
	if res.CurrentVersion != 1 {
		t.Errorf("check reports current_version %d, want 1", res.CurrentVersion)
	}
}

// TestPolicyCheckCompilesForAHost is the reason the endpoint is worth more than
// its size: "will web-01 still reach the database" is the question people have,
// and it is answered here rather than by applying and watching.
func TestPolicyCheckCompilesForAHost(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	web := h.createTaggedHost(t, ts.URL, "policy-web", "10.42.90.1", []string{"web"})
	h.createTaggedHost(t, ts.URL, "policy-db", "10.42.90.2", []string{"db"})

	body := h.checkPolicyFor(t, ts.URL, policyDocV1, "policy-web")
	if body.Membership == nil {
		t.Fatal("check with ?host= returned no host")
	}
	if body.Membership.ID != web.ID {
		t.Errorf("check resolved host %s, want %s", body.Membership.ID, web.ID)
	}
	if !slices.Contains(body.Membership.Tags, "web") {
		t.Errorf("host tags reported as %v, want the web tag — the selector inputs are "+
			"the half of this answer that explains a rule that did not appear", body.Membership.Tags)
	}
	if body.Compiled == nil {
		t.Fatal("check with ?host= returned no compiled rule set")
	}

	// web is a src of the 5432 rule, so it gets an OUTBOUND rule to the db host
	// and no inbound one for that port. Compiling to addresses is the whole
	// design, so the rule names db's address rather than a group.
	if !hasRule(body.Compiled.Outbound, "tcp", "5432", "10.42.90.2/32") {
		t.Errorf("web has no outbound tcp/5432 rule to the db host's address.\noutbound: %+v",
			body.Compiled.Outbound)
	}
	if hasRule(body.Compiled.Inbound, "tcp", "5432", "10.42.90.1/32") {
		t.Errorf("web has an inbound 5432 rule; it is the source of that allowance, not the "+
			"destination.\ninbound: %+v", body.Compiled.Inbound)
	}
	// The "*" rule compiles to the network's prefix rather than to one rule per
	// host, which is what keeps it correct as hosts come and go.
	if !hasRule(body.Compiled.Inbound, "tcp", "22", "10.42.0.0/16") {
		t.Errorf("no inbound ssh rule for the network prefix.\ninbound: %+v", body.Compiled.Inbound)
	}

	// A host that does not exist is a 404 naming it, not a compiled empty set.
	// The failure mode being avoided: a typo'd host name silently answering
	// "this host gets no rules", which reads as a policy problem.
	code, raw := h.adminRawBody(t, http.MethodPost,
		h.policyURL(ts.URL)+"/check?host=no-such-host", policyDocV1)
	if code != http.StatusNotFound {
		t.Errorf("check against an unknown host: %d, want 404 (%s)", code, raw)
	}
}

// TestPolicySelectorNamingNothingIsRefusedAtCheck.
//
// A host: selector that matches nothing is a dangling reference — a typo, or a
// host deleted out from under the policy — and it compiles to an error rather
// than to silence. This is precisely what the check endpoint is for: without it
// the failure lands at render time, on every host, after the document is already
// stored.
func TestPolicySelectorNamingNothingIsRefusedAtCheck(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	h.createTaggedHost(t, ts.URL, "policy-lonely", "10.42.91.1", nil)

	doc := `{"version":1,"allow":[
		{"src":["host:policy-lonely"],"dst":["host:ghost-that-was-deleted"],
		 "proto":"tcp","ports":["443"]}]}`

	code, body := h.adminRawBody(t, http.MethodPost,
		h.policyURL(ts.URL)+"/check?host=policy-lonely", doc)
	if code != http.StatusBadRequest {
		t.Fatalf("a selector naming no host was accepted: %d (%s)", code, body)
	}
	if !strings.Contains(body, "ghost-that-was-deleted") {
		t.Errorf("the refusal does not name the selector that matched nothing: %s", body)
	}
}

// TestPolicyOptInSwitch covers the posture change: the gate, the refusal to
// switch onto nothing, and the mutual exclusion with per-role rules.
func TestPolicyOptInSwitch(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	netURL := ts.URL + "/v1/networks/" + h.netID.String()

	// Switching onto a document that does not exist is refused, and the message
	// has to say why rather than name a constraint. Nebula's firewall is
	// default-deny, so this would be a fleet-wide outage that every host reports
	// as a successful apply.
	code, body := h.adminRaw(t, http.MethodPatch, netURL, wire.UpdateNetworkRequest{
		FirewallSource: ptr(store.FirewallSourcePolicy), AcknowledgeFirewallChange: true,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("switch to policy mode with no document: %d, want 400 (%s)", code, body)
	}
	if !strings.Contains(body, "no policy document") {
		t.Errorf("refusal does not explain there is no document: %s", body)
	}

	if code, _ := h.putPolicy(t, ts.URL, policyDocV1); code != http.StatusOK {
		t.Fatalf("PUT policy: %d", code)
	}

	// With a document but no live hosts the gate does not fire: there is nothing
	// to disrupt, and a confirmation demanded where no harm is possible is what
	// teaches operators to pass the flag reflexively.
	var switched wire.NetworkUpdateResponse
	if code := h.adminReq(t, http.MethodPatch, netURL, wire.UpdateNetworkRequest{
		FirewallSource: ptr(store.FirewallSourcePolicy),
	}, &switched); code != http.StatusOK {
		t.Fatalf("switch on an empty network without an acknowledgement: %d", code)
	}
	if !switched.FirewallSourceChanged {
		t.Error("the switch reported firewall_source_changed=false")
	}
	if switched.FirewallSource != store.FirewallSourcePolicy {
		t.Fatalf("network reports firewall_source %q after switching", switched.FirewallSource)
	}

	// Now a role firewall edit is refused. A rule stored in policy mode renders
	// nowhere, and accepting it would leave an operator certain they had opened a
	// port — the exact dual of a rule they believe they deleted.
	locked := json.RawMessage(`{"inbound":[{"port":"443","proto":"tcp","host":"any"}]}`)
	code, body = h.adminRaw(t, http.MethodPatch, ts.URL+"/v1/roles/"+h.roleID.String(),
		wire.UpdateRoleRequest{Firewall: &locked})
	if code != http.StatusConflict {
		t.Errorf("editing a role's firewall in policy mode: %d, want 409 (%s)", code, body)
	}
	if !strings.Contains(body, "policy document") {
		t.Errorf("the refusal does not explain where the firewall comes from: %s", body)
	}

	// But a role edit that does not touch the firewall is still legal: roles are
	// not obsolete in policy mode, they still carry the groups that go into the
	// certificate.
	newName := "renamed-in-policy-mode"
	var renamed wire.RoleUpdateResponse
	if code := h.adminReq(t, http.MethodPatch, ts.URL+"/v1/roles/"+h.roleID.String(),
		wire.UpdateRoleRequest{Name: &newName}, &renamed); code != http.StatusOK {
		t.Errorf("renaming a role in policy mode: %d, want 200", code)
	}

	// Switching back restores the per-role rules, which were kept rather than
	// deleted — a mode change that destroyed the configuration it switched away
	// from would be one nobody could back out of.
	var back wire.NetworkUpdateResponse
	if code := h.adminReq(t, http.MethodPatch, netURL, wire.UpdateNetworkRequest{
		FirewallSource: ptr(store.FirewallSourceRole),
	}, &back); code != http.StatusOK {
		t.Fatalf("switch back to role mode: %d", code)
	}
	var role wire.RoleResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/roles/"+h.roleID.String(), nil, &role); code != http.StatusOK {
		t.Fatalf("get role: %d", code)
	}
	if len(role.Firewall) == 0 {
		t.Error("the role's firewall rules were destroyed by the switch; switching is " +
			"supposed to be reversible")
	}
}

// TestPolicySwitchIsGatedWhenHostsAreLive is the acknowledgement gate.
//
// The blast radius is the whole network at once and the failure is silent: if the
// new source is narrower, every host applies successfully, reports the new epoch,
// and reads as fully converged while traffic stops. Making the operator say so
// out loud is the only signal there is.
func TestPolicySwitchIsGatedWhenHostsAreLive(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	netURL := ts.URL + "/v1/networks/" + h.netID.String()

	if code, _ := h.putPolicy(t, ts.URL, policyDocV1); code != http.StatusOK {
		t.Fatalf("PUT policy: %d", code)
	}
	host := h.createTaggedHost(t, ts.URL, "policy-gated", "10.42.92.1", []string{"web"})
	h.setState(t, mustUUID(t, host.ID), store.MembershipActive)

	before := h.networkEpochs(t, ts.URL).ConfigEpoch

	code, body := h.adminRaw(t, http.MethodPatch, netURL, wire.UpdateNetworkRequest{
		FirewallSource: ptr(store.FirewallSourcePolicy),
	})
	if code != http.StatusConflict {
		t.Fatalf("unacknowledged switch with a live host: %d, want 409 (%s)", code, body)
	}

	var gate wire.FirewallSourceChangeError
	if err := json.Unmarshal([]byte(body), &gate); err != nil {
		t.Fatalf("decode gate body: %v (%s)", err, body)
	}
	// The host count is the part that matters. A client decoding only "error"
	// tells an operator "this needs acknowledging" without saying how much of
	// their fleet it moves, which is the entire question.
	if gate.MembershipsAffected < 1 {
		t.Errorf("the 409 reports %d hosts affected; a live host exists", gate.MembershipsAffected)
	}
	if gate.From != store.FirewallSourceRole || gate.To != store.FirewallSourcePolicy {
		t.Errorf("the 409 reports %q -> %q", gate.From, gate.To)
	}
	if gate.Detail == "" {
		t.Error("the 409 carries no detail; the consequence is the reason for the gate")
	}

	if after := h.networkEpochs(t, ts.URL).ConfigEpoch; after != before {
		t.Fatalf("config epoch %d -> %d on a REFUSED switch: the gate let the change "+
			"through", before, after)
	}

	// Acknowledged, it proceeds.
	var ok wire.NetworkUpdateResponse
	if code := h.adminReq(t, http.MethodPatch, netURL, wire.UpdateNetworkRequest{
		FirewallSource:            ptr(store.FirewallSourcePolicy),
		AcknowledgeFirewallChange: true,
	}, &ok); code != http.StatusOK {
		t.Fatalf("acknowledged switch: %d", code)
	}
	if !ok.FirewallSourceChanged || ok.MembershipsAffected < 1 {
		t.Errorf("acknowledged switch reported changed=%v affected=%d",
			ok.FirewallSourceChanged, ok.MembershipsAffected)
	}
	if after := h.networkEpochs(t, ts.URL).ConfigEpoch; after <= before {
		t.Fatalf("config epoch %d -> %d: a firewall source change no host is told about "+
			"is one that never takes effect", before, after)
	}

	// Re-issuing the same switch is a no-op and must not wake the fleet again.
	atSwitch := h.networkEpochs(t, ts.URL).ConfigEpoch
	var again wire.NetworkUpdateResponse
	if code := h.adminReq(t, http.MethodPatch, netURL, wire.UpdateNetworkRequest{
		FirewallSource:            ptr(store.FirewallSourcePolicy),
		AcknowledgeFirewallChange: true,
	}, &again); code != http.StatusOK {
		t.Fatalf("re-issued switch: %d", code)
	}
	if again.FirewallSourceChanged {
		t.Error("re-issuing the same switch reported a change")
	}
	if after := h.networkEpochs(t, ts.URL).ConfigEpoch; after != atSwitch {
		t.Errorf("config epoch %d -> %d on a re-issued switch that changed nothing",
			atSwitch, after)
	}
}

// TestPolicyIsRenderedOnlyWhenSwitchedOn is the opt-in enforced where it has to
// be: at the source the renderer reads from.
//
// A stored document that has not been switched on must be invisible to the render
// path — not filtered out later by something that could forget, but never handed
// over in the first place. store.NetworkPolicy is that gate, and it is the only
// place the check exists.
func TestPolicyIsRenderedOnlyWhenSwitchedOn(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	ctx := context.Background()

	if code, _ := h.putPolicy(t, ts.URL, policyDocV1); code != http.StatusOK {
		t.Fatalf("PUT policy: %d", code)
	}

	// Stored, not switched on: the render path is handed nothing at all, which is
	// byte-identical to a network that has no document.
	err := h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		doc, fleet, err := store.NetworkPolicy(ctx, tx, h.netID)
		if err != nil {
			return err
		}
		if doc != nil {
			t.Errorf("a stored but un-switched policy was handed to the renderer (%d bytes); "+
				"it would silently become the firewall", len(doc))
		}
		if fleet != nil {
			t.Errorf("a fleet was read for a network not using policy mode")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	netURL := ts.URL + "/v1/networks/" + h.netID.String()
	if code := h.adminReq(t, http.MethodPatch, netURL, wire.UpdateNetworkRequest{
		FirewallSource: ptr(store.FirewallSourcePolicy),
	}, nil); code != http.StatusOK {
		t.Fatalf("switch to policy mode: %d", code)
	}

	err = h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		doc, _, err := store.NetworkPolicy(ctx, tx, h.netID)
		if err != nil {
			return err
		}
		if len(doc) == 0 {
			t.Fatal("a switched-on network handed the renderer no document; every host " +
				"would render an empty firewall, which is default-deny")
		}
		if _, err := policy.Parse(doc); err != nil {
			t.Errorf("the document handed to the renderer does not parse: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
}

// TestPolicyHistoryIsKept. The reason this is a table and not a column: "what did
// the policy say last Tuesday" is a question an incident asks, and a column
// answers only in the present tense.
func TestPolicyHistoryIsKept(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	ctx := context.Background()

	if code, _ := h.putPolicy(t, ts.URL, policyDocV1); code != http.StatusOK {
		t.Fatalf("PUT v1: %d", code)
	}
	if code, _ := h.putPolicy(t, ts.URL, policyDocV2); code != http.StatusOK {
		t.Fatalf("PUT v2: %d", code)
	}

	err := h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		versions, err := tx.ListPolicyVersions(ctx, h.netID, 10)
		if err != nil {
			return err
		}
		if len(versions) != 2 {
			t.Fatalf("history holds %d versions after two distinct documents, want 2", len(versions))
		}
		if versions[0].Version != 2 || versions[1].Version != 1 {
			t.Errorf("history is not newest-first: %d, %d", versions[0].Version, versions[1].Version)
		}
		// The superseded version is intact, not overwritten in place. That is the
		// whole point.
		old, err := policy.Parse(versions[1].Document)
		if err != nil {
			return err
		}
		if len(old.Allow) != 2 {
			t.Errorf("version 1 holds %d allowances, want the 2 it was written with", len(old.Allow))
		}
		// Each version records the epoch it produced, which is the only join
		// between a policy version and what a host reported applying.
		if versions[0].ConfigEpoch <= versions[1].ConfigEpoch {
			t.Errorf("config epochs do not increase with version: %d then %d",
				versions[1].ConfigEpoch, versions[0].ConfigEpoch)
		}

		// And the point-in-time query the incident actually runs.
		at, err := tx.PolicyAt(ctx, h.netID, versions[1].CreatedAt)
		if err != nil {
			return err
		}
		if at.Version != 1 {
			t.Errorf("PolicyAt(version 1's timestamp) returned version %d", at.Version)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
}

// TestPolicyScopesAreEnforced. A token trusted to read and write networks must
// not reach the firewall for every host in one through the same grant.
func TestPolicyScopesAreEnforced(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var networksOnly wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name:   "policy-scope-" + randSuffix(),
		Scopes: []string{"networks:read", "networks:write", "roles:write"},
	}, &networksOnly); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	if code := h.reqAs(t, networksOnly.Token, http.MethodGet, h.policyURL(ts.URL), nil, nil); code != http.StatusForbidden {
		t.Errorf("GET policy with networks:read: %d, want 403 — the policy document is the "+
			"firewall, not network metadata", code)
	}

	// And the switch, which rides on the network PATCH that this token CAN call.
	// The route declares networks:write; the handler requires policy:write on top
	// of it, because otherwise a token minted to rename networks could replace the
	// firewall on every host in one.
	code, body := h.rawPatchAs(t, networksOnly.Token, ts.URL+"/v1/networks/"+h.netID.String(),
		wire.UpdateNetworkRequest{FirewallSource: ptr(store.FirewallSourcePolicy)})
	if code != http.StatusForbidden {
		t.Errorf("firewall_source switch with only networks:write: %d, want 403 (%s)", code, body)
	}
	if !strings.Contains(body, "policy:write") {
		t.Errorf("the 403 does not name the scope it wants, so the CLI cannot print the "+
			"`orbit token create` that would grant it: %s", body)
	}

	// A rename through the same endpoint still works with networks:write alone.
	// The extra requirement is per-field, not per-route.
	renamed := "renamed-" + randSuffix()
	if code := h.reqAs(t, networksOnly.Token, http.MethodPatch,
		ts.URL+"/v1/networks/"+h.netID.String(),
		wire.UpdateNetworkRequest{Name: &renamed}, nil); code != http.StatusOK {
		t.Errorf("renaming a network with networks:write: %d, want 200", code)
	}
}

//------------------------------------------------------------------------------
// helpers
//------------------------------------------------------------------------------

func documentsEqual(a, b policy.Document) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

func hasRule(rules []wire.PolicyRule, proto, port, cidr string) bool {
	for _, r := range rules {
		if r.Proto == proto && r.Port == port && r.CIDR == cidr {
			return true
		}
	}
	return false
}

// createTaggedHost creates a host with tags, which is what tag: selectors resolve
// against. The harness's own createAndEnroll runs a full enrollment; these tests
// need the row and its addresses, not a certificate.
func (h *harness) createTaggedHost(t *testing.T, baseURL, name, addr string, tags []string) wire.MembershipResponse {
	t.Helper()
	var host wire.MembershipResponse
	if code := h.createHost(t, baseURL, membershipSpec{
		NetworkID: h.netID.String(), Name: name, OverlayAddr: addr,
		RoleID: h.roleID.String(), Tags: tags,
	}, &host); code != http.StatusCreated {
		t.Fatalf("create host %s: %d", name, code)
	}
	return host
}

func (h *harness) checkPolicyFor(t *testing.T, baseURL, doc, host string) wire.PolicyCheckResponse {
	t.Helper()
	code, body := h.adminRawBody(t, http.MethodPost,
		h.policyURL(baseURL)+"/check?host="+host, doc)
	if code != http.StatusOK {
		t.Fatalf("check policy for %s: %d (%s)", host, code, body)
	}
	var out wire.PolicyCheckResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode check response: %v (%s)", err, body)
	}
	return out
}

// rawPatchAs issues a PATCH with a specific token and returns the body, which
// adminReq discards for a failure — and the body is what these assertions are
// about.
func (h *harness) rawPatchAs(t *testing.T, token, url string, body any) (int, string) {
	t.Helper()
	saved := h.token
	h.token = token
	defer func() { h.token = saved }()
	return h.adminRaw(t, http.MethodPatch, url, body)
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return id
}

func randSuffix() string { return uuid.NewString()[:8] }
