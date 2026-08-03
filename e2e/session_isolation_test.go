package e2e

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/web"
)

// THE HARD RULE, asserted over live HTTP in both directions.
//
// /v1 MUST NEVER ACCEPT A SESSION COOKIE. Every route on that surface was
// written assuming bearer authentication, which a browser cannot be made to
// send cross-site — so none of them carry a CSRF defence and several would be
// dangerous without one. DELETE /v1/hosts/{id} takes its reason from a QUERY
// PARAMETER; the moment a cookie reaches it, a link in an email decommissions a
// host and files a reason.
//
// AND THE BROWSER SURFACE MUST NEVER ACCEPT A BEARER TOKEN, so that "the
// console is cookie-only" stays a fact rather than a convention, and so nothing
// gets written against a second, unintended API.
//
// These are the younger siblings of TestAgentAPIAbsentFromPublicListener above.
// That test proves the agent surface is not merely authenticated but
// unroutable; this one proves the two surfaces that DO share a listener cannot
// share a credential.

// serveBothSurfaces mounts /v1 and a stand-in browser surface on ONE mux.
//
// Deliberately the worst case. In production internal/web and the admin API may
// well be separate listeners, and the isolation would then be partly
// topological. Putting them on the same mux removes that comfort: whatever
// keeps the credentials apart here is the middleware and nothing else.
//
// The /ui side is internal/web's OWN mux, not a re-implementation: internal/api
// briefly carried a parallel browser-auth path that nothing called, and it has
// been removed, so this test now exercises the code a running orbitd serves.
func (h *harness) serveBothSurfaces(t *testing.T) *httptest.Server {
	t.Helper()

	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.New(h.store, nil, api.Config{}, discard)

	mux := http.NewServeMux()
	srv.AdminRoutes(mux)

	// The real UI, on the same mux as /v1 — deliberately the worst case. In
	// production these are separate listeners, and separation would then be
	// doing the work; here nothing topological can be, so whatever keeps the
	// two credentials apart is the middleware and only the middleware.
	ui, err := web.New(h.store, nil, web.StoreSessions(h.store), web.Config{}, discard)
	if err != nil {
		t.Fatalf("build the ui: %v", err)
	}
	ui.Routes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// signIn mints a browser session on the harness's bootstrap token, the way a
// login handler will.
func (h *harness) signIn(t *testing.T, readOnly bool) string {
	t.Helper()
	ctx := context.Background()

	sum := sha256.Sum256([]byte(h.token))
	id, err := h.store.AuthenticateToken(ctx, sum[:])
	if err != nil {
		t.Fatalf("resolve the bootstrap token: %v", err)
	}

	from := netip.MustParseAddr("198.51.100.20")
	var cookie string
	if err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		cookie, _, err = tx.CreateUISession(ctx, id.TokenID, readOnly, &from, "e2e-browser")
		return err
	}); err != nil {
		t.Fatalf("CreateUISession: %v", err)
	}
	return cookie
}

// browserReq issues a request carrying a session cookie and nothing else.
func browserReq(t *testing.T, method, url, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: api.SessionCookieName, Value: cookie})
	}
	// Redirects are NOT followed. The browser surface answers an unauthenticated
	// request with a redirect to the login page, not a 401 — correct for a
	// console, where a JSON 401 would be a blank screen. Following it here would
	// turn every such refusal into a 200 on the login page and make an assertion
	// about being refused indistinguishable from one about being let in.
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestSessionCookieIsRefusedByV1 is the direction that matters most.
//
// A cookie that works perfectly on the browser surface must buy nothing at all
// on /v1 — including on the routes a CSRF attack would actually want.
func TestSessionCookieIsRefusedByV1(t *testing.T) {
	h := setup(t)
	ts := h.serveBothSurfaces(t)

	cookie := h.signIn(t, false) // a FULL session: "*" scopes, nothing narrowed

	// It really is a working credential. Without this the rest of the test
	// could pass on a cookie that was never valid.
	if resp := browserReq(t, http.MethodGet, ts.URL+"/ui/networks", cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("the session does not work on the browser surface either (%d); "+
			"this test proves nothing until it does", resp.StatusCode)
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/hosts"},
		{http.MethodGet, "/v1/whoami"},
		{http.MethodPost, "/v1/hosts"},
		// The one that would hurt: a query parameter carries the reason, so a
		// cross-site GET-shaped request is a complete, attributed decommission.
		{http.MethodDelete, "/v1/hosts/00000000-0000-0000-0000-000000000001?reason=csrf"},
		{http.MethodGet, "/v1/tokens"},
		{http.MethodPost, "/v1/tokens"},
	} {
		resp := browserReq(t, tc.method, ts.URL+tc.path, cookie)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with a valid session cookie = %d, want 401.\n"+
				"/v1 has no CSRF defences because it was written for bearer auth; "+
				"honouring a cookie there makes every route on it forgeable.",
				tc.method, tc.path, resp.StatusCode)
		}
	}
}

// TestBearerTokenIsRefusedByTheBrowserSurface is the other direction.
//
// The bootstrap token holds "*" and works on every /v1 route, so if the browser
// surface accepted Authorization headers this would sail through — and the
// console would quietly have become a second admin API with a different set of
// handlers and no route table watching it.
func TestBearerTokenIsRefusedByTheBrowserSurface(t *testing.T) {
	h := setup(t)
	ts := h.serveBothSurfaces(t)

	// 400, not 401, and the difference is deliberate: an Authorization header on
	// the browser surface is a CALLER MISTAKE, not a failed sign-in. 401 would
	// invite a retry with credentials when the credentials are not the problem —
	// and would send a browser to the login page for a request no browser made.
	// The body says so in words; see internal/web.
	for _, path := range []string{"/ui/networks", "/ui/tokens"} {
		if code := h.reqAs(t, h.token, http.MethodGet, ts.URL+path, nil, nil); code != http.StatusBadRequest {
			t.Errorf("GET %s with a valid \"*\" bearer token = %d, want 400", path, code)
		}
	}

	// The same token still works on /v1, so the refusal above is about the
	// surface and not about the credential having gone bad.
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/hosts?network_id="+h.netID.String(), nil, nil); code != http.StatusOK {
		t.Fatalf("the bearer token stopped working on /v1 = %d; the test above proves nothing", code)
	}
}

// TestBearerAndCookieTogetherIsRefused. A request carrying both must not be
// quietly accepted on either surface by whichever credential happens to fit —
// that is how a proxy or a well-meant client ends up escalating one surface's
// credential onto the other.
func TestBearerAndCookieTogetherIsRefused(t *testing.T) {
	h := setup(t)
	ts := h.serveBothSurfaces(t)
	cookie := h.signIn(t, false)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/ui/networks", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.AddCookie(&http.Cookie{Name: api.SessionCookieName, Value: cookie})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Refused on the strength of the Authorization header alone, before the
	// cookie is even read — so a request that carries both cannot be quietly
	// accepted by whichever credential happens to fit.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a request carrying both credentials on the browser surface = %d, want 400",
			resp.StatusCode)
	}
}

// The cookie's attributes are asserted in internal/web's own tests, against the
// writer that actually runs. A copy lived here and checked internal/api's
// parallel implementation — the one nothing called and that has since been
// removed — so it was passing on code no browser ever saw.

// isLoginRedirect reports whether a browser response is the "sign in first"
// answer: a redirect whose destination is the login page.
//
// Checked as a redirect rather than a status code, because which 3xx a console
// uses is a detail and where it sends you is not.
func isLoginRedirect(resp *http.Response) bool {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false
	}
	return strings.Contains(resp.Header.Get("Location"), "/ui/login")
}
