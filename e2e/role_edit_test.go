package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// Role editing is the most common day-2 change on a mesh: one firewall rule
// moves. These tests pin the two properties that make it safe to do casually.
//
//   - An edit that changes something advances the config epoch, so every host
//     carrying the role re-renders. An edit that changes nothing does not, so a
//     reconcile loop re-applying the same desired state is free rather than
//     fleet-wide work.
//   - An edit that changes GROUPS is not the same operation. Groups live in the
//     signed certificate, so the change is not in force until every host has
//     renewed — and the response says so, in a way a caller checking only the
//     status code cannot miss.

// roleUpdateResponse mirrors what PATCH /v1/roles/{id} returns. Declared here
// rather than imported because the API type is unexported; if the two drift,
// these assertions fail, which is the point.
type roleUpdateResponse struct {
	wire.RoleResponse
	Changed                  bool   `json:"changed"`
	GroupsChanged            bool   `json:"groups_changed"`
	HostsAwaitingCertificate int    `json:"hosts_awaiting_certificate"`
	CertificatesConvergeBy   string `json:"certificates_converge_by"`
	Detail                   string `json:"detail"`
}

// adminRaw returns the status and the body, which adminReq deliberately does
// not for a failure: the refusals here are only useful if they name what is
// wrong, so the test has to read them.
func (h *harness) adminRaw(t *testing.T, method, url string, body any) (int, string) {
	t.Helper()

	var rdr io.Reader
	if body != nil {
		b, err := jsonMarshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, url, rdr)
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
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func ptr[T any](v T) *T { return &v }

// TestRoleFirewallEditConverges covers the hot path: a rule changes, the epoch
// advances, and re-sending the same rules does not advance it again.
func TestRoleFirewallEditConverges(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	roleURL := ts.URL + "/v1/roles/" + h.roleID.String()

	// A client cannot edit what it cannot read back, so single-role GET is part
	// of the same surface.
	var role wire.RoleResponse
	if code := h.adminReq(t, http.MethodGet, roleURL, nil, &role); code != http.StatusOK {
		t.Fatalf("get role: %d", code)
	}
	if role.Name != "default" || len(role.Groups) != 1 || role.Groups[0] != "default" {
		t.Fatalf("get role returned %+v", role)
	}

	before := h.networkEpochs(t, ts.URL).ConfigEpoch

	locked := json.RawMessage(`{"inbound":[{"port":"22","proto":"tcp","groups":["default"]}],
	                            "outbound":[{"port":"any","proto":"any","host":"any"}]}`)
	var edited roleUpdateResponse
	if code := h.adminReq(t, http.MethodPatch, roleURL,
		wire.UpdateRoleRequest{Firewall: &locked}, &edited); code != http.StatusOK {
		t.Fatalf("patch firewall: %d", code)
	}
	if !edited.Changed {
		t.Error("a firewall edit reported changed=false")
	}
	if edited.GroupsChanged {
		t.Error("a firewall-only edit reported groups_changed; it does not touch certificates")
	}

	afterEdit := h.networkEpochs(t, ts.URL).ConfigEpoch
	if afterEdit <= before {
		t.Fatalf("config epoch %d -> %d: a firewall edit that no host is told about "+
			"is a rule that never takes effect", before, afterEdit)
	}

	// The same rules again, reformatted. firewall_rules is jsonb and compared
	// as jsonb, so whitespace and key order are not a change — and a no-op
	// PATCH must not wake every agent on the network to re-render a fragment
	// identical to the one it is already running.
	same := json.RawMessage(`{
		"outbound": [ {"host": "any", "proto": "any", "port": "any"} ],
		"inbound":  [ {"groups": ["default"], "proto": "tcp", "port": "22"} ]
	}`)
	var noop roleUpdateResponse
	if code := h.adminReq(t, http.MethodPatch, roleURL,
		wire.UpdateRoleRequest{Firewall: &same}, &noop); code != http.StatusOK {
		t.Fatalf("no-op patch: %d", code)
	}
	if noop.Changed {
		t.Error("re-sending the stored rules reported changed=true")
	}
	if got := h.networkEpochs(t, ts.URL).ConfigEpoch; got != afterEdit {
		t.Errorf("config epoch %d -> %d on a no-op PATCH; every bump is fleet-wide work",
			afterEdit, got)
	}

	// A name-only edit is still an edit, but it renders nothing, so it is not
	// worth a separate assertion beyond "it is accepted and reported".
	var renamed roleUpdateResponse
	if code := h.adminReq(t, http.MethodPatch, roleURL,
		wire.UpdateRoleRequest{Name: ptr("default-renamed")}, &renamed); code != http.StatusOK {
		t.Fatalf("patch name: %d", code)
	}
	if renamed.Name != "default-renamed" || !renamed.Changed {
		t.Errorf("rename returned %+v", renamed)
	}

	// An empty PATCH is a client bug, not a no-op: it is what a request whose
	// pointer fields all failed to serialize looks like.
	if code, body := h.adminRaw(t, http.MethodPatch, roleURL,
		wire.UpdateRoleRequest{}); code != http.StatusBadRequest {
		t.Errorf("empty PATCH = %d (%s), want 400", code, body)
	}
}

// TestRoleEditRejectsBadRules covers the two refusals an edit inherits from
// creation, and they are the reason validation cannot live only on POST.
func TestRoleEditRejectsBadRules(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	roleURL := ts.URL + "/v1/roles/" + h.roleID.String()

	epoch := h.networkEpochs(t, ts.URL).ConfigEpoch

	// Nebula reads only the keys it knows and ignores the rest, so this rule
	// would be stored, rendered, and silently enforced with no group
	// constraint at all. The refusal has to name the key or it is not useful.
	typo := json.RawMessage(`{"inbound":[{"port":"22","proto":"tcp","groupss":["default"]}]}`)
	code, body := h.adminRaw(t, http.MethodPatch, roleURL, wire.UpdateRoleRequest{Firewall: &typo})
	if code != http.StatusBadRequest {
		t.Fatalf("typo'd rule = %d (%s), want 400", code, body)
	}
	if !strings.Contains(body, "groupss") {
		t.Errorf("refusal does not name the offending field: %s", body)
	}

	// The bootstrap CA permits only "default". A group outside it must fail
	// here, while the operator is looking at the role, rather than later as a
	// certificate constraint error during an unrelated enrollment.
	code, body = h.adminRaw(t, http.MethodPatch, roleURL,
		wire.UpdateRoleRequest{Groups: ptr([]string{"default", "admin"})})
	if code != http.StatusBadRequest {
		t.Fatalf("group outside the CA = %d (%s), want 400", code, body)
	}
	if !strings.Contains(body, "admin") {
		t.Errorf("refusal does not name the offending group: %s", body)
	}

	if got := h.networkEpochs(t, ts.URL).ConfigEpoch; got != epoch {
		t.Errorf("config epoch %d -> %d after two rejected edits; nothing was stored", epoch, got)
	}

	var role wire.RoleResponse
	h.adminReq(t, http.MethodGet, roleURL, nil, &role)
	if len(role.Groups) != 1 || role.Groups[0] != "default" {
		t.Errorf("rejected group edit still changed the role: %v", role.Groups)
	}
}

// TestRoleGroupChangeReportsCertificateLag is the one that matters.
//
// Editing firewall rules is configuration and converges in seconds. Editing
// groups changes what goes into the SIGNED CERTIFICATE, and Orbit cannot force
// a reissue — each host renews on its own schedule. An operator who reads a
// 200 and moves on believes a policy change has taken effect when it will not
// for hours, so the response has to say otherwise in the status code, not only
// in a field.
func TestRoleGroupChangeReportsCertificateLag(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))
	roleURL := ts.URL + "/v1/roles/" + h.roleID.String()

	host := h.createAndEnroll(t, ts, "grouped", "10.42.9.1", false, false, nil)

	before := h.networkEpochs(t, ts.URL).ConfigEpoch

	var resp roleUpdateResponse
	code := h.adminReq(t, http.MethodPatch, roleURL,
		wire.UpdateRoleRequest{Groups: ptr([]string{})}, &resp)
	if code != http.StatusAccepted {
		t.Fatalf("group change = %d, want 202: the change is accepted but not yet in force", code)
	}
	if !resp.Changed || !resp.GroupsChanged {
		t.Fatalf("group change reported changed=%v groups_changed=%v", resp.Changed, resp.GroupsChanged)
	}
	if resp.HostsAwaitingCertificate != 1 {
		t.Errorf("hosts_awaiting_certificate = %d, want 1 (%s still holds the old groups)",
			resp.HostsAwaitingCertificate, host.name)
	}
	if resp.Detail == "" {
		t.Error("no detail: the numbers alone do not say what they mean")
	}

	// The deadline is computed from the live certificate row and the agent's
	// renewal policy, which is deterministic per host — so it is a real instant
	// rather than a guess, and it can be checked against the very certificate
	// the host is holding. The agent renews at the midpoint, which the enroll
	// response already reports as RenewAfter, offset by up to ±10% of the
	// lifetime.
	convergeBy, err := time.Parse(time.RFC3339, resp.CertificatesConvergeBy)
	if err != nil {
		t.Fatalf("certificates_converge_by = %q: %v", resp.CertificatesConvergeBy, err)
	}
	midpoint := host.respons.RenewAfter
	jitter := host.respons.NotAfter.Sub(midpoint) / 5 // 10% of the lifetime
	if convergeBy.Before(midpoint.Add(-jitter)) || convergeBy.After(midpoint.Add(jitter)) {
		t.Errorf("certificates_converge_by = %s, want within %v of the certificate midpoint %s",
			convergeBy, jitter, midpoint)
	}
	// And never past the point where the certificate is dead anyway: a deadline
	// after expiry would describe a host that has already fallen off the mesh.
	if !convergeBy.Before(host.respons.NotAfter) {
		t.Errorf("certificates_converge_by %s is at or past the certificate's expiry %s",
			convergeBy, host.respons.NotAfter)
	}

	// The config epoch still advances: the host's rendered fragment is refreshed
	// even though its certificate is not.
	if got := h.networkEpochs(t, ts.URL).ConfigEpoch; got <= before {
		t.Errorf("config epoch %d -> %d on a group change", before, got)
	}

	// Filed under its own action. "Which policy changes were not in force at
	// time T" has to be a WHERE clause, not a scan through metadata.
	entries := h.auditFor(t, ts.URL, "role.groups_changed", h.roleID.String())
	if len(entries) != 1 {
		t.Fatalf("role.groups_changed entries = %d, want 1", len(entries))
	}
	meta := string(entries[0].Meta)
	if !strings.Contains(meta, "hosts_awaiting_certificate") ||
		!strings.Contains(meta, "certificates_converge_by") {
		t.Errorf("audit metadata does not record the lag: %s", meta)
	}
	if plain := h.auditFor(t, ts.URL, "role.updated", h.roleID.String()); len(plain) != 0 {
		t.Errorf("a group change was also filed as role.updated (%d entries); "+
			"that is the entry an incident review would find instead", len(plain))
	}
}

// TestRoleDeleteNamesTheHostsThatBlockIt covers the endpoint whose whole value
// is its error message.
//
// host.role_id is ON DELETE RESTRICT, so the database refuses a delete of a
// role in use no matter what the API does. What the API adds is which hosts —
// and avoiding the raw refusal, which mapErr renders as a foreign key
// violation and would surface as a 404 claiming the role does not exist.
func TestRoleDeleteNamesTheHostsThatBlockIt(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	// An unused role deletes cleanly.
	var spare wire.RoleResponse
	if code := h.adminPost(t, ts.URL+"/v1/roles", wire.CreateRoleRequest{
		NetworkID: h.netID.String(), Name: "spare-" + uuid.NewString()[:8],
		Groups: []string{"default"},
	}, &spare); code != http.StatusCreated {
		t.Fatalf("create spare role: %d", code)
	}
	if code, body := h.adminRaw(t, http.MethodDelete, ts.URL+"/v1/roles/"+spare.ID, nil); code != http.StatusNoContent {
		t.Fatalf("delete unused role = %d (%s), want 204", code, body)
	}
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/roles/"+spare.ID, nil, nil); code != http.StatusNotFound {
		t.Errorf("deleted role still readable: %d", code)
	}

	// One that hosts carry does not, and the refusal names them.
	host := h.createAndEnroll(t, ts, "carrier", "10.42.9.2", false, false, nil)
	code, body := h.adminRaw(t, http.MethodDelete, ts.URL+"/v1/roles/"+h.roleID.String(), nil)
	if code != http.StatusConflict {
		t.Fatalf("delete role in use = %d (%s), want 409", code, body)
	}
	if !strings.Contains(body, host.name) {
		t.Errorf("refusal does not name the host blocking it: %s", body)
	}

	// And the role is still there and still intact.
	var role wire.RoleResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/roles/"+h.roleID.String(), nil, &role); code != http.StatusOK {
		t.Errorf("get role after refused delete: %d", code)
	}
}
