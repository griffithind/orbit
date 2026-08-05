package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
)

// Every template is parsed AND executed with representative data, here.
//
// Parsing alone is not enough and is the trap: html/template compiles a
// reference to a field that does not exist without complaint, and fails at
// execution — which, without this test, means at 3am, as a 500, on the page
// somebody opened because something was already wrong. Executing with data that
// exercises the branches is the only thing that catches it.
//
// TestEveryPageHasAFixture is the other half. It fails when a screen is added
// without a fixture, so this file cannot quietly stop covering the package.

func testServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(nil, nil, nil, Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// testPage builds the layout half of a render, with an identity present so the
// signed-in navigation and the scope-gated controls are exercised rather than
// skipped.
func (s *Server) testPage(title string, data any) *pageData {
	netID := uuid.NewString()
	return &pageData{
		Title:   title,
		Assets:  s.assets,
		CSRF:    "test-csrf-token",
		Actor:   "ops-oncall",
		Scopes:  []string{"*"},
		Version: "test",
		Networks: []networkLink{
			{ID: netID, Slug: "prod", Name: "prod"},
			{ID: uuid.NewString(), Slug: "lab", Name: "lab"},
		},
		CurrentNetwork: netID,
		// More networks than the picker lists, so the "all N networks" fallback is
		// exercised rather than only the short-list path.
		NetworkCount: 42,
		Notice:       "A notice, rendered as a banner.",
		Data:         data,
	}
}

func fixtureNetwork() networkView {
	return networkView{
		ID: uuid.NewString(), Slug: "prod", Name: "prod",
		CIDRs: []string{"10.42.0.0/16"}, ConfigEpoch: 41, BlocklistEpoch: 7,
		FirewallSource: "role", CertTTL: "24h0m0s",
	}
}

// fixtureHost is a host in the interesting state rather than the healthy one:
// behind on config, silent for hours, with a restart outstanding. A fixture that
// only covers the happy path leaves every conditional in the template untested,
// and the conditionals are the parts that render during an incident.
func fixtureHost() membershipView {
	seen := time.Now().Add(-3 * time.Hour)
	return membershipView{
		ID: uuid.NewString(), Name: "web-03", State: store.MembershipActive,
		Badge:        membershipStateBadge(store.MembershipActive),
		OverlayAddrs: []string{"10.42.0.7"},
		RoleID:       uuid.NewString(), RoleName: "web",
		Tags:         []string{"prod", "eu-west"},
		IsRelay:      true,
		IsLighthouse: true,
		StaticAddrs:  []string{"203.0.113.10:4242"},

		NebulaVersion: "v1.11.0", AgentVersion: "v0.9.1",
		LastSeenAt: &seen, CreatedAt: time.Now().Add(-30 * 24 * time.Hour),

		AppliedConfigEpoch: 40, AppliedBlocklistEpoch: 7,
		ConfigEpoch: 41, BlocklistEpoch: 7,
		ConfigBadge: epochBadge(40, 41, store.MembershipActive),
		BlockBadge:  epochBadge(7, 7, store.MembershipActive),

		RestartRequiredEpoch: 41, RestartPending: true,
		ListenPort: 4242, TunDev: "orbit-prod",
	}
}

func fixtureCerts() []certView {
	now := time.Now()
	overdue := store.CertificateRow{
		ID: uuid.New(), CAID: uuid.New(), CAName: "prod-ca-1",
		Fingerprint: strings.Repeat("ab", 32), CertVer: 2, State: store.CertActive,
		NotBefore: now.Add(-30 * time.Hour), NotAfter: now.Add(-6 * time.Hour),
		IssuedAt: now.Add(-30 * time.Hour),
	}
	// Deliberately in the past, so the OVERDUE marker and the expired badge are
	// both rendered by this test rather than only in production.
	old := store.CertificateRow{
		ID: uuid.New(), CAID: uuid.New(), CAName: "prod-ca-0",
		Fingerprint: strings.Repeat("cd", 32), CertVer: 2, State: store.CertSuperseded,
		NotBefore: now.Add(-72 * time.Hour), NotAfter: now.Add(-48 * time.Hour),
		IssuedAt: now.Add(-72 * time.Hour),
	}
	return []certView{newCertView(overdue, now), newCertView(old, now)}
}

func fixtureConvergence() convergenceView {
	seen := time.Now().Add(-90 * time.Minute)
	return convergenceView{
		ConfigEpoch: 41, BlocklistEpoch: 7,
		MembershipsTotal: 204, ConfigApplied: 198, BlockApplied: 204,
		ConfigBadge: convergedBadge(198, 204),
		BlockBadge:  convergedBadge(204, 204),
		Lagging: []laggingView{
			{MembershipID: uuid.NewString(), Name: "db-01", AppliedConfigEpoch: 39, AppliedBlocklistEpoch: 7, LastSeenAt: &seen},
			{MembershipID: uuid.NewString(), Name: "never-seen", AppliedConfigEpoch: 0, AppliedBlocklistEpoch: 0},
		},
		Truncated: true,
	}
}

func fixtureCAs() []caView {
	now := time.Now()
	pending := store.CA{
		ID: uuid.New(), Name: "prod-ca-2", Fingerprint: strings.Repeat("ef", 32),
		State: store.CAPending, SignerRef: "file:///var/lib/orbit/ca-2.key",
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
	}
	retiring := store.CA{
		ID: uuid.New(), Name: "prod-ca-1", Fingerprint: strings.Repeat("ab", 32),
		State: store.CARetiring, SignerRef: "awskms://alias/orbit-prod",
		NotBefore: now.Add(-80 * 24 * time.Hour), NotAfter: now.Add(10 * 24 * time.Hour),
	}
	done := store.CA{
		ID: uuid.New(), Name: "prod-ca-0", Fingerprint: strings.Repeat("cd", 32),
		State: store.CARetiring, SignerRef: "file:///var/lib/orbit/ca-0.key",
		NotBefore: now.Add(-200 * 24 * time.Hour), NotAfter: now.Add(-1 * time.Hour),
	}
	return []caView{
		newCAView(&pending, 0, now),
		newCAView(&retiring, 12, now),
		// Zero live certificates and retiring: the one that renders a Retire
		// button, which is the branch worth exercising.
		newCAView(&done, 0, now),
	}
}

// fixtures maps each page template to representative data.
func fixtures(s *Server) map[string]*pageData {
	now := time.Now()
	net := fixtureNetwork()
	host := fixtureHost()
	certs := fixtureCerts()
	conv := fixtureConvergence()
	cas := fixtureCAs()
	expires := now.Add(48 * time.Hour)
	used := now.Add(-2 * time.Hour)
	revoked := now.Add(-4 * time.Hour)

	rv := rotationView{
		Network: net, CAs: cas, Convergence: conv,
		Pending: &cas[0], Retiring: cas[1:],
		Converged: false, CutOff: 6,
	}
	rv.Step = rotationStepFor(rv)
	rv.Steps = rotationSteps(rv, net.Slug)

	return map[string]*pageData{
		"status.html": s.testPage("not found", statusView{
			Status: 404, Title: "not found",
			Detail: "That host does not exist.\n\nIt may have been deleted.",
			At:     now,
		}),
		"login.html": s.testPage("Sign in", loginView{
			Next: "/ui/memberships/" + host.ID, Note: "Your session has ended.",
			Problem: "That token is not valid.",
		}),
		"networks.html": s.testPage("Networks", networksView{Networks: []networkView{net}}),
		"overview.html": s.testPage("prod", overviewView{
			Network: net, Convergence: conv,
			Expiring: []expiringView{{
				MembershipID: host.ID, MembershipName: host.Name, Short: "abababababababab",
				RenewAt: now.Add(-6 * time.Hour), NotAfter: now.Add(6 * time.Hour),
				LastSeenAt: host.LastSeenAt, Badge: badgeOverdue,
			}},
			Replicas: []replicaView{{
				MembershipID: uuid.NewString(), Addr: "10.42.0.2", AgentPort: 8443, LastSeenAt: now,
			}},
			Push:               pushView{Configured: true, Watchers: 3, Badge: badgeOK("push enabled"), Detail: "Agents are woken by a notification."},
			CAs:                cas,
			RotationInProgress: true,
		}),
		"convergence.html": s.testPage("Convergence", struct {
			Network     networkView
			Convergence convergenceView
		}{net, conv}),
		"memberships.html": s.testPage("Memberships", membershipListView{
			Network: net, Memberships: []membershipView{host},
			Total:      intPtr(204),
			Filter:     membershipFilterView{State: store.MembershipActive, Behind: true, Query: "web", States: listableHostStates},
			NextCursor: "?cursor=abc", PrevURL: "?",
		}),
		"membership.html": s.testPage("web-03", membershipDetailView{
			Membership: host, Network: net, Certificates: certs, More: true,
			ActiveCAName: "prod-ca-2", ActiveCAID: uuid.NewString(),
			Findings: diagnose(host, certs, now, uuid.NewString(), true),
		}),
		"block.html": s.testPage("Block web-03", blockConfirmView{
			Membership: host, Network: net,
			Consequences: []string{"web-03 RELAYS FOR OTHER HOSTS.", "It is a lighthouse."},
		}),
		"membership_new.html": s.testPage("Reserve a place", membershipNewView{
			Network: net,
			Roles:   []roleOption{{ID: host.RoleID, Name: "web"}},
			Form:    newMembershipForm{Name: "web-04", RoleID: host.RoleID},
			Problem: "That name is already taken in this network.",
		}),
		"enroll_code.html": s.testPage("Enrollment code", enrollCodeView{
			Membership: &host, Name: host.Name, Network: net,
			Code: "orbit-code-abcd-efgh", ExpiresAt: expires,
			EnrollURL: "https://orbit.example.com/enroll/v1/enroll",
			Command:   "orbit agent enroll -url https://orbit.example.com/enroll/v1/enroll -code … -network prod",
		}),
		// The reservation variant: no host exists yet, so the page must not
		// render an address or a link to one. Rendered as its own case because
		// a nil Membership is exactly the branch a template is most likely to get
		// wrong and least likely to be exercised by hand.
		"enroll_code.html#reserved": s.testPage("Reservation", enrollCodeView{
			Membership: nil, Name: "web-04", Network: net,
			Code: "orbit-code-ijkl-mnop", ExpiresAt: expires,
			EnrollURL: "https://orbit.example.com",
			Command:   "orbit agent join -url https://orbit.example.com -network prod -code …",
		}),
		"rotation.html": s.testPage("CA rotation", rv),
		"audit.html": s.testPage("Audit", auditView{
			Records: []auditRecordView{{
				At: now, Action: store.ActionMembershipBlocked, ActorType: store.ActorToken,
				ActorDisplay: "ops-oncall", TargetType: "host", TargetID: host.ID,
				SourceIP: "10.0.0.5", Meta: `{"via":"ui"}`, MembershipLink: "/ui/memberships/" + host.ID,
			}, {
				At: now.Add(-time.Hour), Action: store.ActionEnrollFailed, ActorType: store.ActorSystem,
				Meta: `{}`,
			}},
			Filter:  auditFilterView{Action: store.ActionMembershipBlocked, TargetID: host.ID, SinceHours: 24},
			Actions: auditActions, AtLimit: true, Limit: auditPageSize,
		}),
		"tokens.html": s.testPage("API tokens", tokensView{Tokens: []tokenView{
			{
				ID: uuid.NewString(), Name: "ci", Scopes: []string{"memberships:read"},
				CreatedAt: now.Add(-90 * 24 * time.Hour), LastUsedAt: &used,
				Badge: badgeOK("in use"), ExpiresAt: &expires,
			},
			{
				ID: uuid.NewString(), Name: "leaked", Scopes: []string{"*"},
				CreatedAt: now.Add(-10 * 24 * time.Hour), LastUsedAt: &used, RevokedAt: &revoked,
				Badge: badgeBad("USED AFTER REVOCATION"), UsedAfterRevocation: true,
			},
		}, Sessions: []sessionView{
			{
				ID: uuid.NewString(), TokenID: uuid.NewString(), TokenName: "ops",
				Current: true, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(10 * time.Hour),
				LastSeenAt: now.Add(-30 * time.Second), From: "198.51.100.9",
				Agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
				Badge: badgeOK("this browser"),
			},
			{
				// No address and no user agent, which is the row a template
				// written against the happy case renders as an empty cell.
				ID: uuid.NewString(), TokenID: uuid.NewString(), TokenName: "ops",
				CreatedAt: now.Add(-9 * time.Hour), ExpiresAt: now.Add(3 * time.Hour),
				LastSeenAt: now.Add(-20 * time.Minute),
				Badge:      badgeWarn("full access"),
			},
		}, CanRevoke: true}),
	}
}

func intPtr(n int) *int { return &n }

// baseTemplate strips a fixture's "#variant" suffix.
//
// A page with a branch that changes what it renders — enroll_code.html, whose
// Membership is nil for a reservation — needs more than one fixture, and the untaken
// branch is exactly the one nobody looks at by hand. Variants let a template
// carry several while keeping the one-fixture-per-page guard below meaningful.
func baseTemplate(fixture string) string {
	if i := strings.IndexByte(fixture, '#'); i >= 0 {
		return fixture[:i]
	}
	return fixture
}

func TestEveryTemplateRenders(t *testing.T) {
	s := testServer(t)
	fx := fixtures(s)

	// Driven by the FIXTURES rather than the template list, so variants are
	// rendered too. The guard that every template has one is separate.
	names := make([]string, 0, len(fx))
	for name := range fx {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, fixture := range names {
		t.Run(fixture, func(t *testing.T) {
			data := fx[fixture]
			name := baseTemplate(fixture)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
			if err := s.render(rec, req, name, http.StatusOK, data); err != nil {
				t.Fatalf("render: %v", err)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "<!doctype html>") {
				t.Error("no doctype: the layout did not run")
			}
			if !strings.Contains(body, "</main>") {
				t.Error("no main element: the content block did not run")
			}
		})
	}
}

// TestEveryPageHasAFixture fails when a screen is added without one, which is
// the only thing keeping the test above honest.
func TestEveryPageHasAFixture(t *testing.T) {
	s := testServer(t)
	fx := fixtures(s)
	covered := map[string]bool{}
	for fixture := range fx {
		name := baseTemplate(fixture)
		if _, ok := s.tpl.pages[name]; !ok {
			t.Errorf("fixture %s has no page template", fixture)
			continue
		}
		covered[name] = true
	}
	for _, name := range s.tpl.names {
		if !covered[name] {
			t.Errorf("page %s has no fixture; add one so it is executed, not merely parsed", name)
		}
	}
}

// TestNoInlineScriptOrStyle enforces the CSP's precondition.
//
// The policy has no 'unsafe-inline' in script-src or style-src, so one inline
// handler or one style attribute anywhere is a control that silently does
// nothing in a browser — and nothing about it fails in Go. This is what makes
// "no inline scripts or styles" a rule rather than an intention.
func TestNoInlineScriptOrStyle(t *testing.T) {
	s := testServer(t)
	fx := fixtures(s)

	banned := []string{"style=\"", "onclick=", "onsubmit=", "onchange=", "onload=", "javascript:"}
	for _, name := range s.tpl.names {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		if err := s.render(rec, req, name, http.StatusOK, fx[name]); err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		body := rec.Body.String()
		for _, b := range banned {
			if strings.Contains(body, b) {
				t.Errorf("%s contains %q, which the CSP forbids", name, b)
			}
		}
		// The only <script> is the external one the layout emits.
		if n := strings.Count(body, "<script"); n != 1 {
			t.Errorf("%s has %d script tags, want exactly the one external app.js", name, n)
		}
		if !strings.Contains(body, "<script src=\"/ui/static/app.") {
			t.Errorf("%s does not load app.js from a hashed URL", name)
		}
	}
}

// TestEveryActionIsARealForm is the JavaScript-off guarantee, asserted rather
// than assumed.
//
// Every state-changing control in this UI must be a <form method="post"> with a
// real action and a CSRF field. If one ever becomes a button that a script turns
// into a request, this fails — which is the point, because the failure mode
// otherwise is a UI that works on the developer's machine and does nothing at
// all on an operator's locked-down browser.
func TestEveryActionIsARealForm(t *testing.T) {
	s := testServer(t)
	fx := fixtures(s)

	for _, name := range s.tpl.names {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		if err := s.render(rec, req, name, http.StatusOK, fx[name]); err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		body := rec.Body.String()

		for _, form := range splitForms(body) {
			if strings.Contains(form, `method="get"`) {
				continue // filter forms, which change nothing
			}
			if !strings.Contains(form, `method="post"`) {
				t.Errorf("%s: a form has no method=post: %.120s", name, form)
			}
			if !strings.Contains(form, `action="/ui/`) {
				t.Errorf("%s: a form has no same-origin action: %.120s", name, form)
			}
			// The login POST is the one form with no session yet, so it carries
			// no per-session token; it is protected by the origin check alone.
			if strings.Contains(form, `action="/ui/login"`) {
				continue
			}
			if !strings.Contains(form, `name="csrf_token"`) {
				t.Errorf("%s: a form has no CSRF field: %.120s", name, form)
			}
		}
	}
}

func splitForms(body string) []string {
	var out []string
	rest := body
	for {
		i := strings.Index(rest, "<form")
		if i < 0 {
			return out
		}
		rest = rest[i:]
		j := strings.Index(rest, "</form>")
		if j < 0 {
			return append(out, rest)
		}
		out = append(out, rest[:j])
		rest = rest[j:]
	}
}

// TestLiveScreensDegradeWithoutJS asserts the <noscript> fallback is present on
// exactly the screens that claim to update themselves.
//
// A live screen with no fallback is the worst page in the product: with scripts
// disabled it sits there looking authoritative while the fleet moves underneath
// it, and nothing about it says so.
func TestLiveScreensDegradeWithoutJS(t *testing.T) {
	s := testServer(t)
	fx := fixtures(s)

	for _, name := range []string{"overview.html", "convergence.html", "membership.html", "rotation.html"} {
		data := fx[name]
		data.LiveNetwork = uuid.NewString()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
		if err := s.render(rec, req, name, http.StatusOK, data); err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `<noscript><meta http-equiv="refresh" content="15">`) {
			t.Errorf("%s marks itself live but has no noscript refresh", name)
		}
		if !strings.Contains(body, `data-live-network=`) {
			t.Errorf("%s marks itself live but app.js has nothing to key off", name)
		}
	}
}

// TestStoredValuesAreEscaped is the XSS assertion.
//
// The two blobs that look like they want raw rendering — firewall rule JSON and
// a certificate PEM — are exactly the two an attacker would aim at, and both go
// through <pre>{{ . }}</pre>. A host name is the more realistic vector: it is
// operator-supplied, it appears on six screens, and it reaches the template from
// the database rather than from the request that is rendering it.
func TestStoredValuesAreEscaped(t *testing.T) {
	s := testServer(t)
	const payload = `<script>alert(1)</script>`

	host := fixtureHost()
	host.Name = payload
	host.Tags = []string{payload}
	host.RoleName = payload

	data := s.testPage("x", membershipDetailView{
		Membership: host, Network: fixtureNetwork(),
		Certificates: fixtureCerts(),
		Findings:     diagnose(host, nil, time.Now(), "", true),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	if err := s.render(rec, req, "membership.html", http.StatusOK, data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := rec.Body.String()
	if strings.Contains(body, payload) {
		t.Fatal("a stored host name was rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("the payload does not appear escaped either; the fixture did not reach the page")
	}

	// Audit metadata is jsonb and some of it originated in a request.
	auditData := s.testPage("x", auditView{Records: []auditRecordView{{
		At: time.Now(), Action: "membership.deleted", Meta: `{"name":"` + payload + `"}`,
	}}})
	rec = httptest.NewRecorder()
	if err := s.render(rec, req, "audit.html", http.StatusOK, auditData); err != nil {
		t.Fatalf("render audit: %v", err)
	}
	if strings.Contains(rec.Body.String(), payload) {
		t.Fatal("audit metadata was rendered unescaped")
	}
}

//------------------------------------------------------------------------------
// The pieces the templates depend on
//------------------------------------------------------------------------------

func TestDiagnoseNamesTheOverdueRenewal(t *testing.T) {
	now := time.Now()
	seen := now.Add(-2 * time.Minute)
	host := membershipView{State: store.MembershipActive, LastSeenAt: &seen}

	certs := []certView{newCertView(store.CertificateRow{
		ID: uuid.New(), CAID: uuid.New(), CAName: "ca-1", State: store.CertActive,
		NotBefore: now.Add(-20 * time.Hour), NotAfter: now.Add(4 * time.Hour),
	}, now)}
	if !certs[0].Overdue {
		t.Fatal("fixture is not overdue; the test would prove nothing")
	}

	got := diagnose(host, certs, now, certs[0].CAID, true)
	if len(got) == 0 || !strings.Contains(got[0].Summary, "Renewal was due") &&
		!strings.Contains(got[0].Summary, "renewal was due") {
		t.Fatalf("overdue renewal is not the leading finding: %+v", got)
	}
}

func TestDiagnoseHealthyHostSaysSo(t *testing.T) {
	now := time.Now()
	seen := now.Add(-time.Minute)
	host := membershipView{State: store.MembershipActive, LastSeenAt: &seen}
	caID := uuid.NewString()
	certs := []certView{newCertView(store.CertificateRow{
		ID: uuid.New(), CAID: uuid.MustParse(caID), CAName: "ca-1", State: store.CertActive,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(23 * time.Hour),
	}, now)}

	got := diagnose(host, certs, now, caID, true)
	if len(got) != 1 || got[0].Badge.Tone != "ok" {
		t.Fatalf("a healthy host produced findings: %+v", got)
	}
}

// TestEpochBadgeDoesNotCallANewHostBehind guards the one comparison that would
// otherwise make the badge permanently red on a host that is not broken.
func TestEpochBadgeDoesNotCallANewHostBehind(t *testing.T) {
	b := epochBadge(0, 41, store.MembershipCreated)
	if b.Tone != "muted" {
		t.Fatalf("a never-enrolled host reads as %q, want muted", b.Tone)
	}
	if b := epochBadge(40, 41, store.MembershipActive); b.Tone != "warn" {
		t.Fatalf("a behind host reads as %q, want warn", b.Tone)
	}
	if b := epochBadge(41, 41, store.MembershipActive); b.Tone != "ok" {
		t.Fatalf("a converged host reads as %q, want ok", b.Tone)
	}
}

// TestEveryBadgeHasAGlyphAndAWord is the accessibility invariant, checked rather
// than trusted: a badge that is only a colour is unreadable in greyscale and to
// a colourblind reader, and it is exactly the sort of thing that regresses in a
// hurry.
func TestEveryBadgeHasAGlyphAndAWord(t *testing.T) {
	all := []badge{
		badgeOverdue,
		membershipStateBadge(store.MembershipActive), membershipStateBadge(store.MembershipSuspended),
		membershipStateBadge(store.MembershipCreated), membershipStateBadge("weird"),
		caStateBadge(store.CAActive), caStateBadge(store.CAPending),
		caStateBadge(store.CARetiring), caStateBadge(store.CARetired),
		epochBadge(1, 2, store.MembershipActive), convergedBadge(0, 0), convergedBadge(1, 2),
	}
	for _, b := range all {
		if b.Glyph == "" || b.Word == "" || b.Tone == "" {
			t.Errorf("badge %+v is missing a signal", b)
		}
	}
}

func TestAgoAndStamp(t *testing.T) {
	if got := agoPtr(nil); got != "never" {
		t.Errorf("agoPtr(nil) = %q, want never", got)
	}
	if got := stampPtr(nil); got != "—" {
		t.Errorf("stampPtr(nil) = %q", got)
	}
	if got := ago(time.Time{}); got != "never" {
		t.Errorf("ago(zero) = %q, want never", got)
	}
	if got := ago(time.Now().Add(2 * time.Hour)); !strings.HasPrefix(got, "in ") {
		t.Errorf("a future time reads as %q; it must not say 'ago'", got)
	}
	if got := pct(0, 0); got != "n/a" {
		t.Errorf("pct(0,0) = %q, want n/a", got)
	}
}

//------------------------------------------------------------------------------
// Assets
//------------------------------------------------------------------------------

func TestAssetsAreContentHashedAndImmutable(t *testing.T) {
	s := testServer(t)
	if s.assets.CSS == "" || s.assets.JS == "" || s.assets.Favicon == "" {
		t.Fatalf("assets missing: %+v", s.assets)
	}
	if !strings.HasPrefix(s.assets.CSS, "/ui/static/app.") || !strings.HasSuffix(s.assets.CSS, ".css") {
		t.Fatalf("stylesheet is not at a hashed path: %s", s.assets.CSS)
	}

	h := s.assets.handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, s.assets.CSS, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("stylesheet: %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("Cache-Control = %q, want immutable", got)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		// embed.FS modtimes are zero, so ServeContent's own conditional handling
		// is useless; an explicit ETag is the only validator there is.
		t.Fatal("no ETag: the embedded asset has no usable validator without one")
	}

	// The conditional request a proxy that ignores immutable would make.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, s.assets.CSS, nil)
	req.Header.Set("If-None-Match", etag)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("If-None-Match returned %d, want 304", rec.Code)
	}

	// A stale hash must not be answered with the current bytes: the old URL
	// promised those bytes forever.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/static/app.deadbeef.css", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("stale asset URL returned %d, want 404", rec.Code)
	}
}

//------------------------------------------------------------------------------
// Startup validation
//------------------------------------------------------------------------------

func TestNormalizeAddr(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"8081":            "127.0.0.1:8081",
		":8081":           "127.0.0.1:8081",
		"127.0.0.1:8081":  "127.0.0.1:8081",
		"0.0.0.0:8081":    "0.0.0.0:8081",
		"[::1]:8081":      "[::1]:8081",
		"orbit.local:443": "orbit.local:443",
	}
	for in, want := range cases {
		if got := NormalizeAddr(in); got != want {
			t.Errorf("NormalizeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckExposureRefusesCleartextOnNonLoopback(t *testing.T) {
	if err := CheckExposure("", ""); err != nil {
		t.Errorf("a disabled UI must not be refused: %v", err)
	}
	if err := CheckExposure("127.0.0.1:8081", ""); err != nil {
		t.Errorf("loopback with no -ui-url must start: %v", err)
	}
	if err := CheckExposure("[::1]:8081", ""); err != nil {
		t.Errorf("IPv6 loopback must start: %v", err)
	}
	if err := CheckExposure("localhost:8081", ""); err != nil {
		t.Errorf("localhost must start: %v", err)
	}
	if err := CheckExposure("0.0.0.0:8081", ""); err == nil {
		t.Fatal("a UI on every interface with no https front door was allowed to start")
	}
	if err := CheckExposure("0.0.0.0:8081", "http://orbit.example.com"); err == nil {
		t.Fatal("a cleartext -ui-url was accepted; the __Host- cookie cannot be stored over it")
	}
	if err := CheckExposure("0.0.0.0:8081", "https://orbit.example.com"); err != nil {
		t.Errorf("an https front door must be accepted: %v", err)
	}
	// The refusal has to be usable at 3am, not merely correct.
	err := CheckExposure("0.0.0.0:8081", "")
	if !strings.Contains(err.Error(), "ssh -N -L") {
		t.Error("the refusal does not tell the operator how to reach the UI instead")
	}
}

func TestSafeNextRefusesOffOriginRedirects(t *testing.T) {
	// The login page is where a credential is typed, so an open redirect here is
	// the highest-value phish in the product.
	bad := []string{
		"https://evil.example/ui/",
		"//evil.example",
		`/\evil.example`,
		"/v1/memberships",
		"javascript:alert(1)",
		"",
	}
	for _, in := range bad {
		if got := safeNext(in); got != "/ui/" {
			t.Errorf("safeNext(%q) = %q, want the fallback", in, got)
		}
	}
	if got := safeNext("/ui/memberships/abc?x=1"); got != "/ui/memberships/abc?x=1" {
		t.Errorf("safeNext dropped a legitimate destination: %q", got)
	}
}

func TestClientAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	r.RemoteAddr = "10.0.0.5:5000"
	got := clientAddr(r)
	if got == nil || *got != netip.MustParseAddr("10.0.0.5") {
		t.Fatalf("clientAddr = %v", got)
	}
	r.RemoteAddr = "not-an-address"
	if clientAddr(r) != nil {
		t.Fatal("an unparseable RemoteAddr must not become a fake source address")
	}
}
