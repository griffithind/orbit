package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// TestAdminResourceLifecycle walks the operator surface: create a network, a
// role, a CA, activate it, mint a scoped token, and read the audit trail.
func TestAdminResourceLifecycle(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	// Network names are unique across the deployment now that there is one
	// organization, so fixtures must not hardcode them.
	var net wire.NetworkResponse
	if code := h.adminPost(t, ts.URL+"/v1/networks", wire.CreateNetworkRequest{
		Name: "prod-" + uuid.NewString()[:8], CIDRs: []string{"10.77.0.0/16"}, CertTTL: "12h",
	}, &net); code != http.StatusCreated {
		t.Fatalf("create network: %d", code)
	}
	if net.CertTTL != "12h0m0s" {
		t.Errorf("cert_ttl = %q, want 12h", net.CertTTL)
	}

	// A CA must be constrained. Nebula has no intermediate CAs, so an
	// unconstrained one can mint any identity in the mesh.
	if code := h.adminPost(t, ts.URL+"/v1/cas", wire.CreateCARequest{
		NetworkID: net.ID, Name: "unscoped", SignerRef: "file://" + h.caKey,
	}, nil); code != http.StatusBadRequest {
		t.Errorf("unconstrained CA creation = %d, want 400", code)
	}

	var caResp wire.CAResponse
	if code := h.adminPost(t, ts.URL+"/v1/cas", wire.CreateCARequest{
		NetworkID: net.ID, Name: "prod-ca", SignerRef: "file://" + h.caKey,
		Networks: []string{"10.77.0.0/16"}, Groups: []string{"web", "db"}, Days: 30,
	}, &caResp); code != http.StatusCreated {
		t.Fatalf("create CA: %d", code)
	}
	// Created pending: a CA must reach every trust bundle before it signs.
	if caResp.State != "pending" {
		t.Errorf("new CA state = %q, want pending", caResp.State)
	}
	if caResp.CertPEM == "" {
		t.Error("CA response omits the PEM operators need for the trust bundle")
	}

	if code := h.adminPost(t, ts.URL+"/v1/cas/"+caResp.ID+"/activate", nil, &caResp); code != http.StatusOK {
		t.Fatalf("activate CA: %d", code)
	}
	if caResp.State != "active" {
		t.Errorf("activated CA state = %q, want active", caResp.State)
	}

	// A role whose groups the CA does not permit must be refused here, not
	// later as a confusing certificate constraint error.
	if code := h.adminPost(t, ts.URL+"/v1/roles", wire.CreateRoleRequest{
		NetworkID: net.ID, Name: "bad", Groups: []string{"admin"},
	}, nil); code != http.StatusBadRequest {
		t.Errorf("role with a group outside the CA = %d, want 400", code)
	}

	var role wire.RoleResponse
	if code := h.adminPost(t, ts.URL+"/v1/roles", wire.CreateRoleRequest{
		NetworkID: net.ID, Name: "web", Groups: []string{"web"},
		Firewall: json.RawMessage(`{"inbound":[{"port":"443","proto":"tcp","groups":["web"]}],
		                            "outbound":[{"port":"any","proto":"any","host":"any"}]}`),
	}, &role); code != http.StatusCreated {
		t.Fatalf("create role: %d", code)
	}

	// A typo'd rule must be rejected. Nebula would accept it and produce a rule
	// with no group constraint at all.
	if code := h.adminPost(t, ts.URL+"/v1/roles", wire.CreateRoleRequest{
		NetworkID: net.ID, Name: "typo",
		Firewall: json.RawMessage(`{"inbound":[{"port":"22","proto":"tcp","groupss":["web"]}]}`),
	}, nil); code != http.StatusBadRequest {
		t.Errorf("role with a typo'd firewall key = %d, want 400", code)
	}

	// Creating a role must advance the config epoch so hosts pick it up.
	var nets []wire.NetworkResponse
	h.adminReq(t, http.MethodGet, ts.URL+"/v1/networks", nil, &nets)
	var found *wire.NetworkResponse
	for i := range nets {
		if nets[i].ID == net.ID {
			found = &nets[i]
		}
	}
	if found == nil {
		t.Fatal("created network is not listed")
	}
	if found.ConfigEpoch <= net.ConfigEpoch {
		t.Errorf("config epoch did not advance after a role change: %d -> %d",
			net.ConfigEpoch, found.ConfigEpoch)
	}

	// The audit trail must show all of it.
	// The audit log is deployment-wide, so filter to this test's own objects
	// rather than counting everything.
	seen := map[string]bool{}
	for _, target := range []string{net.ID, caResp.ID, role.ID} {
		var audit []wire.AuditRecordResponse
		h.adminReq(t, http.MethodGet, ts.URL+"/v1/audit-logs?target_id="+target, nil, &audit)
		for _, a := range audit {
			seen[a.Action] = true
		}
	}
	for _, want := range []string{"network.created", "ca.created", "ca.activated", "role.created"} {
		if !seen[want] {
			t.Errorf("audit log is missing %q", want)
		}
	}
}

// TestTokenScopesAreEnforced proves the scope model actually restricts, rather
// than merely being recorded.
func TestTokenScopesAreEnforced(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	// Mint a read-only token using the bootstrap token.
	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "read-only-" + uuid.NewString()[:8], Scopes: []string{"memberships:read", "networks:read"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}
	if tok.Token == "" {
		t.Fatal("token response has no plaintext; it is returned exactly once")
	}

	// Reads work.
	restricted := &harness{t: t, store: h.store,
		netID: h.netID, roleID: h.roleID, token: tok.Token, caKey: h.caKey}
	var nets []wire.NetworkResponse
	if code := restricted.adminReq(t, http.MethodGet, ts.URL+"/v1/networks", nil, &nets); code != http.StatusOK {
		t.Errorf("read with networks:read = %d, want 200", code)
	}

	// Writes do not.
	if code := restricted.adminPost(t, ts.URL+"/v1/networks", wire.CreateNetworkRequest{
		Name: "sneaky-" + uuid.NewString()[:8], CIDRs: []string{"10.88.0.0/16"},
	}, nil); code != http.StatusForbidden {
		t.Errorf("write with a read-only token = %d, want 403", code)
	}
	if code := restricted.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "escalate-" + uuid.NewString()[:8], Scopes: []string{"*"},
	}, nil); code != http.StatusForbidden {
		t.Errorf("a read-only token minted itself a wildcard token: %d, want 403", code)
	}
}

// TestConvergenceRendersForHumans covers the terminal view. Convergence gates
// CA rotation and is watched while a revocation lands; both happen at a shell.
func TestConvergenceRendersForHumans(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var host wire.MembershipResponse
	h.createHost(t, ts.URL, membershipSpec{
		NetworkID: h.netID.String(), Name: "laggard", OverlayAddr: "10.42.30.5",
		RoleID: h.roleID.String(),
	}, &host)

	// Move the network's epoch forward so the host is behind.
	if code := h.adminPost(t, ts.URL+"/v1/roles", wire.CreateRoleRequest{
		NetworkID: h.netID.String(), Name: "bump-" + host.ID[:8],
	}, nil); code != http.StatusCreated {
		t.Fatalf("create role: %d", code)
	}

	req, _ := http.NewRequest(http.MethodGet,
		ts.URL+"/v1/networks/"+h.netID.String()+"/convergence?format=text", nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	out := string(body)

	for _, want := range []string{"config", "blocklist", "epoch"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered convergence is missing %q:\n%s", want, out)
		}
	}
	// A host that has never reported must be legible, not a zero timestamp.
	if strings.Contains(out, "0001-01-01") {
		t.Errorf("rendered a zero timestamp instead of \"never\":\n%s", out)
	}
	t.Logf("convergence:\n%s", out)

	// JSON must still be the default, or every script breaks.
	var j wire.ConvergenceResponse
	if code := h.adminReq(t, http.MethodGet,
		ts.URL+"/v1/networks/"+h.netID.String()+"/convergence", nil, &j); code != http.StatusOK {
		t.Fatalf("json convergence: %d", code)
	}
	if j.ConfigEpoch == 0 {
		t.Error("json convergence is empty")
	}
}
