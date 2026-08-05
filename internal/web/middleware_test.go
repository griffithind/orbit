package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
)

// The security properties of this surface, asserted without a database.
//
// These run in milliseconds, so they run on every save. The equivalents that
// need real rows live in e2e/ui_security_test.go; these are the ones that must
// never be skipped because Postgres was not up.

// fakeSessions is the session layer, stubbed. What this package needs from it
// is five methods, and this is the proof that the interface is small enough to
// be worth having.
type fakeSessions struct {
	identity *store.Identity
	err      error
	revoked  map[string]bool
	// sessions is what List returns. Nil is a legitimate answer and several
	// tests rely on it: a handler must not assume the list is non-empty just
	// because the caller is holding one of the things in it.
	sessions []store.UISession
}

func (f *fakeSessions) Create(context.Context, uuid.UUID, bool, *netip.Addr, string) (string, time.Time, error) {
	return "session-value", time.Now().Add(time.Hour), nil
}

func (f *fakeSessions) Resolve(_ context.Context, v string) (*store.Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.revoked[v] || f.identity == nil {
		return nil, store.ErrNotFound
	}
	return f.identity, nil
}

func (f *fakeSessions) Revoke(_ context.Context, v string) error {
	if f.revoked == nil {
		f.revoked = map[string]bool{}
	}
	f.revoked[v] = true
	return nil
}

func (f *fakeSessions) List(context.Context, string) ([]store.UISession, error) {
	return f.sessions, f.err
}

func (f *fakeSessions) RevokeByID(_ context.Context, id uuid.UUID, _ store.Identity) error {
	if f.revoked == nil {
		f.revoked = map[string]bool{}
	}
	f.revoked[id.String()] = true
	return nil
}

// guardedServer returns a server whose only route exercises the middleware.
func guardedServer(t *testing.T, scope string, sess Sessions) (*Server, http.Handler) {
	t.Helper()
	s := testServer(t)
	s.sessions = sess

	mux := http.NewServeMux()
	reached := func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Reached", "yes")
		_, _ = w.Write([]byte("ok"))
		return nil
	}
	mux.Handle("GET /ui/guarded", s.page(s.authed(scope, reached)))
	mux.Handle("POST /ui/guarded", s.page(s.authed(scope, reached)))
	return s, mux
}

func identity(scopes ...string) *store.Identity {
	return &store.Identity{
		Kind: store.ActorToken, Subject: uuid.NewString(),
		Display: "ops-oncall", Scopes: scopes, TokenID: uuid.New(),
	}
}

// browserGet is a request shaped the way a browser actually sends one, which
// matters because the CSRF layer reads exactly these headers.
func browserGet(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

func browserPost(s *Server, path, cookie string, form url.Values) *http.Request {
	if form == nil {
		form = url.Values{}
	}
	if cookie != "" {
		form.Set(csrfField, s.csrfToken(cookie))
	}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Origin", "http://example.com")
	r.Host = "example.com"
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})
	}
	return r
}

//------------------------------------------------------------------------------

// TestUIRejectsBearerTokens is the half of the credential separation this
// package owns. The other half — /v1 never accepting the session cookie — is
// asserted alongside the session layer.
func TestUIRejectsBearerTokens(t *testing.T) {
	sess := &fakeSessions{identity: identity("*")}
	s, h := guardedServer(t, "", sess)

	req := browserGet("/ui/guarded")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "session-value"})
	req.Header.Set("Authorization", "Bearer orbat_something")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; a bearer token must be refused, not ignored", rec.Code)
	}
	if rec.Header().Get("X-Reached") != "" {
		t.Fatal("the handler ran; the request was served under the cookie while carrying a token")
	}
	if !strings.Contains(rec.Body.String(), "/v1") {
		t.Error("the refusal does not point at the surface the token belongs on")
	}

	// Any Authorization scheme, not only Bearer.
	req = browserGet("/ui/guarded")
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Basic auth: status = %d, want 400", rec.Code)
	}

	// And the same rule on the event stream, which does not go through page().
	rec = httptest.NewRecorder()
	streamReq := httptest.NewRequest(http.MethodGet, "/ui/events?network="+uuid.NewString(), nil)
	streamReq.Header.Set("Authorization", "Bearer orbat_something")
	s.stream(s.authed("networks:read", func(http.ResponseWriter, *http.Request) error {
		t.Fatal("the event stream served a request carrying a bearer token")
		return nil
	})).ServeHTTP(rec, streamReq)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("event stream: status = %d, want 400", rec.Code)
	}
}

func TestSecurityHeadersOnEveryHTMLResponse(t *testing.T) {
	sess := &fakeSessions{identity: identity("*")}
	_, h := guardedServer(t, "", sess)

	// Both a success and a refusal: the headers on the error path are the ones
	// nobody remembers to check.
	for _, tc := range []struct {
		name   string
		req    *http.Request
		cookie bool
	}{
		{"authenticated", browserGet("/ui/guarded"), true},
		{"unauthenticated", browserGet("/ui/guarded"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			if tc.cookie {
				req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "session-value"})
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			got := rec.Header()
			csp := got.Get("Content-Security-Policy")
			if csp == "" {
				t.Fatal("no Content-Security-Policy")
			}
			for _, want := range []string{
				"default-src 'none'", "script-src 'self'", "style-src 'self'",
				"form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'",
			} {
				if !strings.Contains(csp, want) {
					t.Errorf("CSP is missing %q: %s", want, csp)
				}
			}
			if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
				t.Errorf("CSP permits inline execution: %s", csp)
			}
			if got.Get("X-Content-Type-Options") != "nosniff" {
				t.Error("no nosniff")
			}
			if got.Get("Referrer-Policy") != "no-referrer" {
				t.Errorf("Referrer-Policy = %q, want no-referrer", got.Get("Referrer-Policy"))
			}
			// An enrollment code and a new token are rendered once; no-cache
			// would still let the back button re-render them from the buffer.
			if got.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got.Get("Cache-Control"))
			}
		})
	}
}

func TestUnauthenticatedGETRedirectsToLoginKeepingTheDestination(t *testing.T) {
	_, h := guardedServer(t, "", &fakeSessions{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, browserGet("/ui/guarded?x=1"))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != "/ui/login" {
		t.Fatalf("Location = %s", loc)
	}
	// The link an operator follows from a pager points at a host, and landing on
	// an overview instead is where a UI stops being faster than the CLI.
	if got := loc.Query().Get("next"); got != "/ui/guarded?x=1" {
		t.Errorf("next = %q, want the original destination", got)
	}
}

// TestUnauthenticatedPOSTIsNotRedirected: a POST cannot be replayed after
// signing in, so bouncing it would silently drop the action.
func TestUnauthenticatedPOSTIsNotRedirected(t *testing.T) {
	s, h := guardedServer(t, "", &fakeSessions{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, browserPost(s, "/ui/guarded", "", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not performed") {
		t.Error("the page does not say the action did not happen")
	}
}

func TestCSRF(t *testing.T) {
	sess := &fakeSessions{identity: identity("*")}
	s, h := guardedServer(t, "", sess)
	const cookie = "session-value"

	t.Run("a well-formed same-origin POST succeeds", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, browserPost(s, "/ui/guarded", cookie, nil))
		if rec.Header().Get("X-Reached") != "yes" {
			t.Fatalf("a legitimate POST was refused: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("cross-site is refused", func(t *testing.T) {
		req := browserPost(s, "/ui/guarded", cookie, nil)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Origin", "https://evil.example")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if rec.Header().Get("X-Reached") != "" {
			t.Fatal("a cross-site POST reached the handler")
		}
	})

	t.Run("a mismatched Origin is refused", func(t *testing.T) {
		req := browserPost(s, "/ui/guarded", cookie, nil)
		req.Header.Del("Sec-Fetch-Site")
		req.Header.Set("Origin", "https://evil.example")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("no origin headers at all is refused", func(t *testing.T) {
		// The standard library allows this so non-browser clients keep working.
		// Nothing that legitimately POSTs here is a non-browser client — that is
		// what /v1 is for — so the allowance is a gap this surface closes.
		req := browserPost(s, "/ui/guarded", cookie, nil)
		req.Header.Del("Sec-Fetch-Site")
		req.Header.Del("Origin")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("a missing form token is refused", func(t *testing.T) {
		req := browserPost(s, "/ui/guarded", "", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "nothing was changed") {
			t.Error("the refusal does not reassure that no change was made")
		}
	})

	t.Run("another session's form token is refused", func(t *testing.T) {
		form := url.Values{csrfField: {s.csrfToken("someone-elses-session")}}
		req := httptest.NewRequest(http.MethodPost, "/ui/guarded", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("a GET is never gated on a token", func(t *testing.T) {
		req := browserGet("/ui/guarded")
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("X-Reached") != "yes" {
			t.Fatalf("a GET was refused: %d", rec.Code)
		}
	})
}

// TestCSRFTokenIsPerSession: a token minted for one session must be worthless in
// another, or the third CSRF layer collapses into the first two.
func TestCSRFTokenIsPerSession(t *testing.T) {
	s := testServer(t)
	a := s.csrfToken("session-a")
	b := s.csrfToken("session-b")
	if a == b {
		t.Fatal("two sessions share a CSRF token")
	}
	if a == "" || strings.Contains(a, "session-a") {
		t.Fatal("the token leaks the cookie value it was derived from")
	}
	if s.csrfToken("session-a") != a {
		t.Fatal("the derivation is not stable; every page load would invalidate the last form")
	}
}

func TestScopeIsCheckedWithTheSameRuleTheAPIUses(t *testing.T) {
	_, h := guardedServer(t, "memberships:block", &fakeSessions{identity: identity("memberships:read")})

	req := browserGet("/ui/guarded")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "session-value"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "memberships:block") {
		t.Error("the refusal does not name the missing scope")
	}

	// A wildcard passes, exactly as it does on /v1.
	_, h = guardedServer(t, "memberships:block", &fakeSessions{identity: identity("*")})
	rec = httptest.NewRecorder()
	req = browserGet("/ui/guarded")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "session-value"})
	h.ServeHTTP(rec, req)
	if rec.Header().Get("X-Reached") != "yes" {
		t.Fatalf("a wildcard token was refused: %d", rec.Code)
	}
}

// TestRevokedSessionClearsTheCookie: leaving a dead cookie in the browser means
// every later request carries a value that will never work again.
func TestRevokedSessionClearsTheCookie(t *testing.T) {
	sess := &fakeSessions{identity: identity("*"), revoked: map[string]bool{"session-value": true}}
	_, h := guardedServer(t, "", sess)

	req := browserGet("/ui/guarded")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "session-value"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want a redirect to the login form", rec.Code)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("the dead session cookie was not cleared")
	}
}

// TestSessionCookieAttributes pins the properties the whole CSRF design rests
// on. SameSite in particular: Strict would make a link from Slack or PagerDuty
// land on a logged-out page, which during an incident reads as "I am locked
// out".
func TestSessionCookieAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	setSessionCookie(rec, "value", time.Now().Add(time.Hour))

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("wrote %d cookies", len(cookies))
	}
	c := cookies[0]

	if c.Name != "__Host-orbit_session" {
		t.Errorf("name = %q; the __Host- prefix is what stops a sibling hostname planting one", c.Name)
	}
	if !c.Secure {
		t.Error("not Secure")
	}
	if !c.HttpOnly {
		t.Error("not HttpOnly; a script that could read it could forge the CSRF token")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q; __Host- requires /", c.Path)
	}
	if c.Domain != "" {
		t.Errorf("Domain = %q; __Host- forbids one", c.Domain)
	}
}

func TestSafeMethods(t *testing.T) {
	// The CSRF check depends on every GET here being a read. A GET that changed
	// something would be reachable from an <img> tag.
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if !safeMethod(m) {
			t.Errorf("%s should be safe", m)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if safeMethod(m) {
			t.Errorf("%s must not be treated as safe", m)
		}
	}
}
