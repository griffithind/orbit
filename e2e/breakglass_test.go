package e2e

import (
	"net/http"
	"os"
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

// TestCheckBreakGlassScript runs the real script from the real Makefile target,
// because a recovery check that is only verified in principle is the same
// untested belief it exists to replace.
//
// Each case is a way the check must NOT silently pass.
func TestCheckBreakGlassScript(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	good := runTokenCreate(t, "script-ok-"+uuid.NewString()[:8], "*")
	narrow := runTokenCreate(t, "script-narrow-"+uuid.NewString()[:8], "hosts:read")

	cases := []struct {
		name     string
		token    string
		url      string
		wantOK   bool
		contains string
	}{
		{"valid", good, ts.URL, true, "break-glass token valid"},
		// The case a plain 200-check would miss entirely: this token
		// authenticates perfectly and would fail at the moment it was needed.
		{"scopes narrowed", narrow, ts.URL, false, "no longer holds"},
		{"rejected", "orbat_not-a-real-token", ts.URL, false, "401"},
		{"unreachable", good, "http://127.0.0.1:1", false, "cannot reach"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", "../scripts/check-break-glass.sh")
			cmd.Env = append(os.Environ(),
				"ORBIT_BREAK_GLASS="+tc.token,
				"ORBIT_URL="+tc.url,
			)
			out, err := cmd.CombinedOutput()
			text := string(out)

			if tc.wantOK && err != nil {
				t.Fatalf("expected success, got %v\n%s", err, text)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("expected a non-zero exit, got success\n%s", text)
			}
			if !strings.Contains(text, tc.contains) {
				t.Errorf("output did not mention %q:\n%s", tc.contains, text)
			}
			// The token must never appear in output a cron job would mail or a
			// CI job would archive.
			if tc.token != "" && strings.Contains(text, tc.token) {
				t.Errorf("the script printed the token:\n%s", text)
			}
		})
	}
}

// TestCheckBreakGlassNeedsAToken: exiting 0 with no token configured would make
// an unconfigured cron job look like a passing check forever.
func TestCheckBreakGlassNeedsAToken(t *testing.T) {
	cmd := exec.Command("sh", "../scripts/check-break-glass.sh")
	cmd.Env = append(os.Environ(), "ORBIT_BREAK_GLASS=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("no token configured but the check passed:\n%s", out)
	}
	if !strings.Contains(string(out), "ORBIT_BREAK_GLASS") {
		t.Errorf("error did not name the variable to set:\n%s", out)
	}
}

// TestWhoAmINeedsNoScope. The check calls /v1/whoami with a credential whose
// scopes it is trying to discover, so requiring one would make the endpoint
// unable to answer for exactly the tokens worth asking about.
func TestWhoAmINeedsNoScope(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "scopeless-" + uuid.NewString()[:8], Scopes: []string{"audit:read"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	var who wire.WhoAmIResponse
	if code := h.reqAs(t, tok.Token, http.MethodGet, ts.URL+"/v1/whoami", nil, &who); code != http.StatusOK {
		t.Fatalf("whoami with a narrow token = %d, want 200", code)
	}
	if who.Kind != store.ActorToken || who.ID != tok.ID {
		t.Errorf("whoami = %+v, want kind=token id=%s", who, tok.ID)
	}
	if who.Unscoped {
		t.Error("a token holding only audit:read reported itself as unscoped")
	}

	// And it does not echo the credential back.
	if strings.Contains(who.ID+who.Name, tok.Token) {
		t.Error("whoami echoed the token")
	}
}
