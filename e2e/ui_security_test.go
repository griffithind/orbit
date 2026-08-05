package e2e

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/web"
)

// The operator UI, against a real database and the real session layer.
//
// internal/web has its own fast tests for the middleware and the templates,
// stubbed to run without Postgres. These are the ones that need real rows: a
// session that a real token actually minted, a scope narrowing that
// store.ResolveSession actually performed, and a block that really did move a
// host's state.

// These tests use web.StoreSessions — the same adapter cmd/orbitd wires — rather
// than a copy of it. A copy lived here until sessions grew a listing: it was
// written to "exercise the real store methods", and the moment the interface
// gained a method it became a second thing to keep in step, which is the exact
// failure StoreSessions exists to prevent.

// uiHarness is a running operator UI and a browser-shaped client for it.
type uiHarness struct {
	*harness
	url    string
	client *http.Client
}

// serveWeb starts the UI on its own httptest server, exactly as orbitd starts it
// on its own listener.
func (h *harness) serveWeb(t *testing.T) *uiHarness {
	return h.serveWebWith(t, nil)
}

// serveWebWith is serveWeb with an epoch notifier, so the event stream has
// something to deliver.
func (h *harness) serveWebWith(t *testing.T, notifier *notify.Notifier) *uiHarness {
	t.Helper()

	registry := ca.NewRegistry(h.vault.SignerFactory())
	t.Cleanup(func() { registry.Close() })

	svc := enroll.NewService(h.store, registry, enroll.Config{
		NetworkIdentity: h.vault.NetworkIdentity,
		Paths:           nebulacfg.DefaultPaths(),
		ListenPort:      4242,
		EnrollURL:       "https://orbit.example.com/enroll/v1/enroll",
	})

	ui, err := web.New(h.store, svc, web.StoreSessions(h.store), web.Config{Notifier: notifier},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}

	ts := httptest.NewServer(ui.Handler())
	t.Cleanup(ts.Close)

	// A cookie jar, so the session behaves the way it does in a browser rather
	// than being threaded by hand — which is the only way to notice that a
	// __Host- cookie was refused.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		// Redirects are followed by hand: a login flow that silently follows a
		// 303 cannot assert where it was sent.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &uiHarness{harness: h, url: ts.URL, client: client}
}

// get issues a request shaped the way a browser sends one.
func (u *uiHarness) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u.url+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := u.client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (u *uiHarness) post(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u.url+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", u.url)
	resp, err := u.client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// csrfFrom pulls the hidden form token out of a rendered page.
//
// Parsed out of the HTML rather than computed, which is the point: it proves the
// token the server accepts is the one it actually put on the page, and a change
// to either side that breaks that pairing fails here rather than in a browser.
func csrfFrom(t *testing.T, html string) string {
	t.Helper()
	const marker = `name="csrf_token" value="`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatal("no csrf_token field on the page")
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatal("malformed csrf_token field")
	}
	return rest[:j]
}

// signIn completes the real login flow: fetch the form, post the token, keep the
// cookie. fullAccess mirrors the checkbox — off means a read-only session, which
// is what the form defaults to.
func (u *uiHarness) signInBrowser(t *testing.T, fullAccess bool) {
	t.Helper()

	resp := u.get(t, "/ui/login")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login form: %d", resp.StatusCode)
	}

	form := url.Values{"token": {u.token}}
	if fullAccess {
		form.Set("full_access", "1")
	}
	resp = u.post(t, "/ui/login", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in: %d\n%s", resp.StatusCode, body(t, resp))
	}

	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == web.SessionCookie {
			found = true
			if !c.Secure || !c.HttpOnly {
				t.Errorf("session cookie is not Secure+HttpOnly: %+v", c)
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax so a link from Slack still lands signed in", c.SameSite)
			}
		}
	}
	if !found {
		t.Fatal("sign-in set no session cookie")
	}

	// The jar drops a Secure cookie on an http:// origin, so the tests thread it
	// explicitly. That is a property of httptest, not of the cookie: a real
	// deployment either terminates TLS in front of this or binds loopback, which
	// browsers treat as a secure context.
	u.adoptCookie(t, resp)
}

func (u *uiHarness) adoptCookie(t *testing.T, resp *http.Response) {
	t.Helper()
	base, err := url.Parse(u.url)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range resp.Cookies() {
		if c.Name != web.SessionCookie {
			continue
		}
		// Stored without Secure so net/http/cookiejar will hand it back over the
		// test server's plain http origin.
		u.client.Jar.SetCookies(base, []*http.Cookie{{Name: c.Name, Value: c.Value, Path: "/"}})
	}
}

//------------------------------------------------------------------------------

// TestUIRefusesBearerTokens is this package's half of the credential separation.
// The mirror image — /v1 refusing the session cookie — belongs with the session
// layer, and the two together are what keep a stolen credential of either kind
// off the other's surface.
func TestUIRefusesBearerTokens(t *testing.T) {
	u := setup(t).serveWeb(t)
	u.signInBrowser(t, true)

	req, err := http.NewRequest(http.MethodGet, u.url+"/ui/networks/"+u.netID.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	// A valid token, a valid session cookie, and the header the UI must refuse.
	req.Header.Set("Authorization", "Bearer "+u.token)

	resp, err := u.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: a bearer token on the UI must be refused, not "+
			"silently served under whatever cookie the browser attached", resp.StatusCode)
	}
	if page := body(t, resp); !strings.Contains(page, "/v1") {
		t.Error("the refusal does not point at the surface the token belongs on")
	}
}

func TestUIResponseHeaders(t *testing.T) {
	u := setup(t).serveWeb(t)
	u.signInBrowser(t, true)

	resp := u.get(t, "/ui/networks/"+u.netID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview: %d", resp.StatusCode)
	}

	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'none'", "script-src 'self'", "style-src 'self'",
		"form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP permits inline execution: %s", csp)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", got)
	}
	// An enrollment code is rendered once and must not survive a back button.
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	// Assets are the exception, and deliberately so: content-hashed URLs are
	// immutable, and they carry no secrets.
	page := body(t, resp)
	cssPath := extractAttr(t, page, `<link rel="stylesheet" href="`)
	asset := u.get(t, cssPath)
	if asset.StatusCode != http.StatusOK {
		t.Fatalf("stylesheet %s: %d", cssPath, asset.StatusCode)
	}
	if got := asset.Header.Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("asset Cache-Control = %q, want immutable", got)
	}
	if asset.Header.Get("ETag") == "" {
		t.Error("asset has no ETag; embed.FS modtimes are zero, so there is no other validator")
	}
}

func extractAttr(t *testing.T, html, marker string) string {
	t.Helper()
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatalf("marker %q not found on the page", marker)
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("malformed attribute after %q", marker)
	}
	return rest[:j]
}

func TestUIUnauthenticatedRedirectsAndKeepsTheDestination(t *testing.T) {
	u := setup(t).serveWeb(t)

	target := "/ui/networks/" + u.netID.String()
	resp := u.get(t, target)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != "/ui/login" {
		t.Fatalf("Location = %s", loc)
	}
	if got := loc.Query().Get("next"); got != target {
		t.Errorf("next = %q, want %q: a link from a pager must land on the host it names", got, target)
	}
}

func TestUICrossOriginPostIsRefused(t *testing.T) {
	u := setup(t).serveWeb(t)
	u.signInBrowser(t, true)

	page := body(t, u.get(t, "/ui/networks/"+u.netID.String()))
	token := csrfFrom(t, page)

	// Everything about this request is legitimate except where it came from.
	req, err := http.NewRequest(http.MethodPost, u.url+"/ui/logout",
		strings.NewReader(url.Values{"csrf_token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://evil.example")

	resp, err := u.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	// And the session is untouched: a refused CSRF attempt must not sign the
	// operator out, which would be a denial of service dressed as a defence.
	if got := u.get(t, "/ui/networks/"+u.netID.String()); got.StatusCode != http.StatusOK {
		t.Fatalf("the session did not survive a refused cross-origin POST: %d", got.StatusCode)
	}
}

func TestUIFormTokenIsRequired(t *testing.T) {
	u := setup(t).serveWeb(t)
	u.signInBrowser(t, true)

	// Same origin, real session, no form token.
	resp := u.post(t, "/ui/logout", url.Values{})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if page := body(t, resp); !strings.Contains(page, "nothing was changed") {
		t.Error("the refusal does not say the action did not happen")
	}
}

// TestUIReadOnlySessionCannotBlock is the whole point of the read-only default.
//
// The token is a wildcard, so this proves the narrowing happens in the session
// rather than in the token: the same credential, signed in without ticking the
// box, cannot reach a control that changes anything.
func TestUIReadOnlySessionCannotBlock(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	membershipID := h.createHostRow(t, "read-only-target")

	u.signInBrowser(t, false) // the default: read-only

	page := body(t, u.get(t, "/ui/memberships/"+membershipID.String()))
	if !strings.Contains(page, "read-only") {
		t.Error("a read-only session is not marked as one; an operator would hunt for a missing button")
	}
	if strings.Contains(page, `href="/ui/memberships/`+membershipID.String()+`/block"`) {
		t.Error("a read-only session was offered a Block control")
	}

	// And the route itself refuses, not just the rendering. A UI that only hides
	// a control has not restricted anything.
	resp := u.get(t, "/ui/memberships/"+membershipID.String()+"/block")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("block confirmation: status = %d, want 403", resp.StatusCode)
	}
	if page := body(t, resp); !strings.Contains(page, "memberships:block") {
		t.Error("the refusal does not name the missing scope")
	}
}

// TestUISignOutEndsTheSessionButNotTheToken is the property that makes a session
// worth having: closing a browser must not revoke the credential an operator's
// shell is also using.
func TestUISignOutEndsTheSessionButNotTheToken(t *testing.T) {
	u := setup(t).serveWeb(t)
	u.signInBrowser(t, true)

	page := body(t, u.get(t, "/ui/networks/"+u.netID.String()))
	resp := u.post(t, "/ui/logout", url.Values{"csrf_token": {csrfFrom(t, page)}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", resp.StatusCode)
	}

	// The browser is signed out.
	if got := u.get(t, "/ui/networks/"+u.netID.String()); got.StatusCode != http.StatusSeeOther {
		t.Fatalf("the session survived sign-out: %d", got.StatusCode)
	}

	// The token still authenticates.
	sum := sha256.Sum256([]byte(u.token))
	id, err := u.store.AuthenticateToken(context.Background(), sum[:])
	if err != nil {
		t.Fatalf("signing out revoked the API token: %v", err)
	}
	if id == nil {
		t.Fatal("no identity")
	}
}

// createHostRow creates a host directly through the store.
//
// Not through the JSON API, because these tests are about the UI surface and
// routing a fixture through a second HTTP server would make a failure there look
// like a failure here.
func (h *harness) createHostRow(t *testing.T, name string) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	var host store.Membership
	err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		net, err := tx.GetNetwork(ctx, h.netID)
		if err != nil {
			return err
		}
		// A membership cannot exist without a device, so one is recorded here
		// too. The machine it describes never runs — this fixture exists so a
		// page has something to render.
		d := store.Device{PublicKey: testDeviceKey(t)}
		if err := tx.SeeDevice(ctx, &d); err != nil {
			return err
		}
		host = store.Membership{NetworkID: h.netID, Name: name, RoleID: &h.roleID, DeviceID: &d.ID}
		return tx.CreateHostAllocating(ctx, net, &host, netip.Prefix{})
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	return host.ID
}

//------------------------------------------------------------------------------
// Listing and ending browser sessions
//------------------------------------------------------------------------------

// newBrowser is a second, independent browser against the same server: its own
// cookie jar, signing in with the same token. That is the situation the session
// list exists for — one credential, more than one browser holding it, and no
// way to tell them apart from the token row alone.
func (u *uiHarness) newBrowser(t *testing.T) *uiHarness {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &uiHarness{
		harness: u.harness,
		url:     u.url,
		client: &http.Client{
			Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// sessionIDs pulls the session ids off the rendered tokens page, from the forms
// that would actually be submitted. Reading them out of the HTML rather than
// out of the database is deliberate: it proves the page offers a control for
// each session, which is the half a store-level test cannot see.
func sessionIDs(html string) []string {
	var out []string
	rest := html
	const marker = `action="/ui/sessions/`
	for {
		i := strings.Index(rest, marker)
		if i < 0 {
			return out
		}
		rest = rest[i+len(marker):]
		j := strings.Index(rest, "/revoke")
		if j < 0 {
			return out
		}
		out = append(out, rest[:j])
	}
}

// TestUISessionListShowsEveryBrowserAndEndsOne is the whole feature end to end:
// two browsers on one token, both visible, one ended, the other and the token
// itself untouched.
//
// The last part is the reason any of this exists. Before it, closing one
// forgotten browser meant revoking the token — which also stops the operator's
// shell, their CI, and anything else holding the same credential. An operator
// facing that choice mid-incident does not close the browser.
func TestUISessionListShowsEveryBrowserAndEndsOne(t *testing.T) {
	h := setup(t)
	first := h.serveWeb(t)
	first.signInBrowser(t, true)

	second := first.newBrowser(t)
	second.signInBrowser(t, true)

	page := body(t, first.get(t, "/ui/tokens"))
	ids := sessionIDs(page)
	if len(ids) < 2 {
		t.Fatalf("the tokens page offers %d sign-out controls, want at least the "+
			"2 browsers signed in\n%s", len(ids), page)
	}
	if !strings.Contains(page, "this browser") {
		t.Error("no session is marked as the caller's own. Every row carries a " +
			"sign-out button; without the mark, the likeliest use of one is an " +
			"operator ending their own session mid-incident")
	}

	// Both browsers see the same rows, so the other one is whichever this
	// browser did not claim as its own.
	firstOwn := ownSessionID(t, first)
	var other string
	for _, id := range ids {
		if id != firstOwn {
			other = id
			break
		}
	}
	if other == "" {
		t.Fatal("could not identify the other browser's session")
	}

	form := url.Values{"csrf_token": {csrfFrom(t, page)}}
	resp := first.post(t, "/ui/sessions/"+other+"/revoke", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke = %d\n%s", resp.StatusCode, body(t, resp))
	}

	// The other browser is out, on its next request.
	resp = second.get(t, "/ui/tokens")
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("the revoked browser got %d, want a redirect to the login page",
			resp.StatusCode)
	}

	// This one is not. That also settles the token: ResolveSession joins
	// orbit.api_token on every request, so a session that still resolves is a
	// token that was not revoked along with the browser.
	if got := first.get(t, "/ui/tokens"); got.StatusCode != http.StatusOK {
		t.Errorf("ending another session ended this one: %d", got.StatusCode)
	}
}

// ownSessionID asks a browser which listed session is its own, by finding the
// row the server marked. The mark comes from a cookie-hash comparison in
// store.ListUISessions, so this also exercises that.
func ownSessionID(t *testing.T, u *uiHarness) string {
	t.Helper()
	html := body(t, u.get(t, "/ui/tokens"))
	// The badge word sits in the row before the form action, so walk rows.
	for _, row := range strings.Split(html, "<tr>") {
		if !strings.Contains(row, "this browser") {
			continue
		}
		for _, id := range sessionIDs(row) {
			return id
		}
	}
	t.Fatal("no row is marked as this browser's own session")
	return ""
}

// TestUIRevokingYourOwnSessionSaysSo. Ending the session you are using is
// allowed — the operator may be on the twin of the browser they are trying to
// close — but landing on a login page with no explanation reads as a bug, and
// the generic "this action was not performed" message would be a lie: it was.
func TestUIRevokingYourOwnSessionSaysSo(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	u.signInBrowser(t, true)

	page := body(t, u.get(t, "/ui/tokens"))
	own := ownSessionID(t, u)

	form := url.Values{"csrf_token": {csrfFrom(t, page)}}
	resp := u.post(t, "/ui/sessions/"+own+"/revoke", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke own = %d\n%s", resp.StatusCode, body(t, resp))
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/ui/login") {
		t.Fatalf("Location = %q, want the login page", loc)
	}
	if !strings.Contains(loc, "note=") {
		t.Error("sent to the login page with no explanation of why")
	}

	// And the session really is gone, not just redirected away from.
	if got := u.get(t, "/ui/tokens"); got.StatusCode != http.StatusSeeOther {
		t.Errorf("the session survived its own revocation: %d", got.StatusCode)
	}
}

// TestUIReadOnlySessionCannotEndSessions. tokens:read shows the list;
// tokens:write is what ends a session. A read-only session is the default at
// sign-in, so this is the common case, not the edge one.
func TestUIReadOnlySessionCannotEndSessions(t *testing.T) {
	h := setup(t)
	full := h.serveWeb(t)
	full.signInBrowser(t, true)
	target := ownSessionID(t, full)

	ro := full.newBrowser(t)
	ro.signInBrowser(t, false)

	page := body(t, ro.get(t, "/ui/tokens"))
	if strings.Contains(page, "/revoke") {
		t.Error("a read-only session is offered sign-out controls it cannot use")
	}

	// And the control being absent is not the enforcement. Post anyway, with a
	// valid CSRF token — the layout's sign-out form carries one on every page,
	// so a read-only session has no trouble producing one. Hiding a button is
	// presentation; the scope check is the control.
	resp := ro.post(t, "/ui/sessions/"+target+"/revoke",
		url.Values{"csrf_token": {csrfFrom(t, page)}})
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("a read-only session ended another session")
	}
	if got := full.get(t, "/ui/tokens"); got.StatusCode != http.StatusOK {
		t.Errorf("the targeted session was ended by a read-only caller: %d", got.StatusCode)
	}
}
