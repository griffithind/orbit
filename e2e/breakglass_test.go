package e2e

import (
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// TestBreakGlassTokenWorksWithNoOtherToken is the whole reason the offline
// command exists.
//
// POST /v1/tokens requires a token, so losing every admin credential leaves no
// API path back in. This drives the real binary against the real database and
// then uses the result against the real API — the sequence an operator would
// run when locked out.
func TestBreakGlassTokenWorksWithNoOtherToken(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	name := "break-glass-" + uuid.NewString()[:8]
	token := runTokenCreate(t, name, "*")

	if !strings.HasPrefix(token, store.APITokenPrefix) {
		t.Fatalf("token %q lacks the %q prefix that identifies it as an Orbit token",
			token, store.APITokenPrefix)
	}

	// It authenticates, and "*" really does pass every scope check.
	if code := h.reqAs(t, token, http.MethodGet,
		ts.URL+"/v1/hosts?network_id="+h.netID.String(), nil, nil); code != http.StatusOK {
		t.Errorf("break-glass token on hosts:read = %d, want 200", code)
	}
	var netsOut []wire.NetworkResponse
	if code := h.reqAs(t, token, http.MethodGet, ts.URL+"/v1/networks", nil, &netsOut); code != http.StatusOK {
		t.Errorf("break-glass token on networks:read = %d, want 200", code)
	}
}

// TestBreakGlassTokenIsAudited. A credential appearing in the database with no
// record of its creation is the shape of an attacker establishing persistence;
// a legitimate break-glass token must not be indistinguishable from one.
func TestBreakGlassTokenIsAudited(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	name := "audited-glass-" + uuid.NewString()[:8]
	token := runTokenCreate(t, name, "*")

	// Find it in the listing to learn its id.
	var list []wire.TokenResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/tokens", nil, &list); code != http.StatusOK {
		t.Fatalf("list tokens: %d", code)
	}
	var id string
	for _, tok := range list {
		if tok.Name == name {
			id = tok.ID
		}
	}
	if id == "" {
		t.Fatal("offline-created token does not appear in the API listing")
	}

	entries := h.auditFor(t, ts.URL, store.ActionTokenCreated, id)
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries for the offline token, want 1", len(entries))
	}
	// Attributed to the system: there is no authenticated actor on the command
	// line, and claiming otherwise would overstate what is known.
	if entries[0].ActorType != store.ActorSystem {
		t.Errorf("actor_type = %q, want %q", entries[0].ActorType, store.ActorSystem)
	}
	if !strings.Contains(string(entries[0].Meta), "orbitd token create") {
		t.Errorf("audit meta %q does not record how the token was created",
			string(entries[0].Meta))
	}

	// And it can be retired through the ordinary path once a narrower token is
	// in place — break-glass is not a credential that escapes revocation.
	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/tokens/"+id, nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoke break-glass token: %d", code)
	}
	if code := h.reqAs(t, token, http.MethodGet, ts.URL+"/v1/networks", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("revoked break-glass token = %d, want 401", code)
	}
}

// TestTokenCreateRejectsAnEmptyName: the name is what the audit log will say
// about every action the token takes, so an unnamed one is not worth having.
func TestTokenCreateRejectsAnEmptyName(t *testing.T) {
	setup(t) // skips if Postgres is unavailable

	cmd := exec.Command("go", "run", "../cmd/orbitd", "token", "create",
		"-dsn", dsn("ORBIT_TEST_APP_DSN", appDSN), "-scopes", "*")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("token create with no -name succeeded: %s", out)
	}
	if !strings.Contains(string(out), "-name is required") {
		t.Errorf("error did not explain the missing flag: %s", out)
	}
}

// runTokenCreate invokes the real binary and returns the plaintext token.
//
// The token is the only thing on stdout, deliberately, so it can be piped
// straight into a password manager. This test depends on that and would catch a
// change that started printing prose there.
func runTokenCreate(t *testing.T, name, scopes string) string {
	t.Helper()

	cmd := exec.Command("go", "run", "../cmd/orbitd", "token", "create",
		"-dsn", dsn("ORBIT_TEST_APP_DSN", appDSN),
		"-name", name, "-scopes", scopes)
	var stderr strings.Builder
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("orbitd token create: %v\n%s", err, stderr.String())
	}

	token := strings.TrimSpace(string(out))
	if strings.ContainsAny(token, " \n") {
		t.Fatalf("stdout carried more than the token, breaking the pipe-to-a-secret-store case: %q", token)
	}
	return token
}
