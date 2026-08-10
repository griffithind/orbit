package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/store"
)

// The incident core, walked the way an operator walks it — and walked with
// JAVASCRIPT DISABLED, because that is what this client is. It follows links,
// posts forms, and never executes a line of app.js.
//
// That is the strongest statement available without a headless browser, and a
// headless browser is exactly the toolchain this design exists to avoid: it
// would reintroduce a node dependency into the test suite of a binary whose
// selling point is that it has none.

// overdueHost creates a host holding an active certificate that is PAST its
// renewal midpoint — the state the host detail page exists to explain.
func (h *harness) overdueHost(t *testing.T, name string) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	membershipID := h.createHostRow(t, name)
	now := time.Now()

	err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		ca, err := tx.GetActiveCA(ctx, h.netID)
		if err != nil {
			return err
		}
		// A 24 hour lifetime with 20 hours elapsed: renewal was due at the
		// midpoint, four hours in the past, and there are four hours left before
		// it expires. That is precisely the window the agent's 50% rule reserves
		// for recovery, and a host sitting in it is a renewal that has been
		// failing for hours with nothing else saying so.
		cert := store.Certificate{
			MembershipID: membershipID,
			CAID:         ca.ID,
			// Unique per call: certificate.fingerprint is globally unique, and two
			// tests seeding the same literal collide in a way that reads as a bug
			// in the code under test rather than in the fixture.
			Fingerprint: strings.ReplaceAll(uuid.NewString(), "-", "") +
				strings.ReplaceAll(uuid.NewString(), "-", ""),
			PEM:       "-----BEGIN NEBULA CERTIFICATE-----\nnot a real certificate\n-----END NEBULA CERTIFICATE-----\n",
			CertVer:   2,
			NotBefore: now.Add(-20 * time.Hour),
			NotAfter:  now.Add(4 * time.Hour),
			State:     store.CertActive,
		}
		if err := tx.InsertCertificate(ctx, &cert); err != nil {
			return err
		}
		return tx.SetHostState(ctx, membershipID, store.MembershipActive)
	})
	if err != nil {
		t.Fatalf("seed an overdue certificate: %v", err)
	}
	return membershipID
}

// TestUIHostDetailDiagnosesAnOverdueRenewal.
//
// The host detail page is the most important page in the product because it
// answers one question — why is this host not renewing — and this is that
// question, asked of a host in the exact state that makes it urgent.
func TestUIHostDetailDiagnosesAnOverdueRenewal(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	membershipID := h.overdueHost(t, "overdue-web-01")

	u.signInBrowser(t, true)

	page := body(t, u.get(t, "/ui/memberships/"+membershipID.String()))

	// The marker, in words. Not a colour, not a red row: OVERDUE is readable in
	// a greyscale screenshot pasted into a ticket.
	if !strings.Contains(page, "OVERDUE") {
		t.Error("the page does not mark the certificate's renew-at as overdue")
	}
	// The diagnosis, as a sentence rather than three fields to compare.
	if !strings.Contains(page, "Renewal was due") && !strings.Contains(page, "renewal was due") {
		t.Error("the page does not say renewal was due")
	}
	// The issuing CA, which is the third leg of the diagnosis: renew-at, plus
	// last-seen, plus which authority signed this.
	if !strings.Contains(page, "e2e-ca") {
		t.Error("the page does not name the issuing CA")
	}
	if !strings.Contains(page, "Last seen") {
		t.Error("the page does not report last-seen")
	}
	// A host that has never reported is a different problem from one that
	// reported an hour ago, and a zero timestamp makes them look the same.
	if !strings.Contains(page, "never") {
		t.Error("a host that has never reported does not say so")
	}
}

// TestUIBlockAHostWithoutJavaScript is the incident action, end to end, with no
// scripting whatsoever: a link to a confirmation page, then a form post.
func TestUIBlockAHostWithoutJavaScript(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	membershipID := h.overdueHost(t, "block-me-01")

	u.signInBrowser(t, true)

	// 1. The host page offers a LINK to the confirmation, not a scripted button.
	detail := body(t, u.get(t, "/ui/memberships/"+membershipID.String()))
	confirmPath := "/ui/memberships/" + membershipID.String() + "/block"
	if !strings.Contains(detail, `href="`+confirmPath+`"`) {
		t.Fatal("no link to the block confirmation; the action is not reachable without scripting")
	}

	// 2. The confirmation page says what blocking THIS host costs, which is the
	// thing a confirm() dialog cannot do.
	confirm := body(t, u.get(t, confirmPath))
	if !strings.Contains(confirm, "reversible") {
		t.Error("the confirmation does not say blocking is reversible; " +
			"an operator who thinks it is not will hesitate at the wrong moment")
	}
	if !strings.Contains(confirm, `<form method="post" action="`+confirmPath+`">`) {
		t.Error("the confirmation has no real form; it would do nothing without scripting")
	}

	// 3. Post the form, exactly as a browser with no scripts would.
	resp := u.post(t, confirmPath, url.Values{"csrf_token": {csrfFrom(t, confirm)}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("block: %d\n%s", resp.StatusCode, body(t, resp))
	}
	// Post/Redirect/Get, so a refresh does not block it a second time.
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/ui/memberships/"+membershipID.String()) {
		t.Errorf("Location = %q, want the host page", loc)
	}

	// 4. It really happened.
	ctx := context.Background()
	var host *store.Membership
	if err := h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		host, err = tx.GetHost(ctx, membershipID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if host.State != store.MembershipSuspended {
		t.Fatalf("host state = %q, want suspended", host.State)
	}

	// 5. And it is attributed, with the source address and a marker saying a
	// person did it from a browser rather than a script hitting /v1.
	var entries []store.AuditRecord
	if err := h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		entries, err = tx.ListAudit(ctx, store.AuditFilter{
			Action: store.ActionMembershipBlocked, TargetID: membershipID.String(),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("blocking a host from the UI wrote no audit entry")
	}
	// Decoded rather than string-matched: Postgres stores jsonb normalized, so
	// the bytes that come back are not the bytes that went in.
	var meta map[string]any
	if err := json.Unmarshal(entries[0].Meta, &meta); err != nil {
		t.Fatalf("audit metadata is not JSON: %s", entries[0].Meta)
	}
	if meta["via"] != "ui" {
		t.Errorf("the audit entry does not record that this came from the UI: %s", entries[0].Meta)
	}
	if entries[0].SourceIP == nil {
		t.Error("the audit entry has no source address; a UI action came from a person at a browser")
	}

	// 6. The page now offers Unblock instead, so the action is reversible from
	// the same screen it was taken on.
	after := body(t, u.get(t, "/ui/memberships/"+membershipID.String()))
	if !strings.Contains(after, "/unblock") {
		t.Error("a blocked host offers no way back")
	}
}

// TestUINoScreenRequiresJavaScript walks every screen and asserts none of them
// smuggles behaviour into a script.
//
// Two properties, both checked on the real rendered output rather than on the
// templates: nothing executes inline (which the CSP would block anyway, so an
// inline handler is a control that silently does nothing), and every mutation is
// a real form with a real action.
func TestUINoScreenRequiresJavaScript(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	membershipID := h.overdueHost(t, "js-off-01")
	u.signInBrowser(t, true)

	paths := []string{
		"/ui/",
		"/ui/networks",
		"/ui/networks/" + h.netID.String(),
		"/ui/networks/" + h.netID.String() + "/convergence",
		"/ui/networks/" + h.netID.String() + "/hosts",
		"/ui/networks/" + h.netID.String() + "/hosts/new",
		"/ui/networks/" + h.netID.String() + "/rotation",
		"/ui/memberships/" + membershipID.String(),
		"/ui/memberships/" + membershipID.String() + "/block",
		"/ui/audit",
		"/ui/tokens",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp := u.get(t, path)
			// /ui/ redirects to the single network's overview.
			if resp.StatusCode == http.StatusSeeOther {
				return
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			page := body(t, resp)

			for _, banned := range []string{"onclick=", "onsubmit=", "onload=", "style=\"", "javascript:"} {
				if strings.Contains(page, banned) {
					t.Errorf("contains %q, which the CSP forbids and which would not run", banned)
				}
			}
			if n := strings.Count(page, "<script"); n != 1 {
				t.Errorf("%d script tags; want exactly the one external app.js", n)
			}

			// Every non-GET form is a real POST to a same-origin action.
			for _, form := range strings.Split(page, "<form")[1:] {
				if end := strings.Index(form, "</form>"); end >= 0 {
					form = form[:end]
				}
				if strings.Contains(form, `method="get"`) {
					continue
				}
				if !strings.Contains(form, `method="post"`) || !strings.Contains(form, `action="/ui/`) {
					t.Errorf("a form is not a real same-origin POST: %.120s", form)
				}
			}
		})
	}
}

// TestUILiveScreensCarryANoScriptFallback.
//
// A live page with scripts disabled is the worst page in the product: it looks
// authoritative and stops being true. The meta refresh is what keeps it honest.
func TestUILiveScreensCarryANoScriptFallback(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	u.signInBrowser(t, true)

	for _, path := range []string{
		"/ui/networks/" + h.netID.String(),
		"/ui/networks/" + h.netID.String() + "/convergence",
	} {
		page := body(t, u.get(t, path))
		if !strings.Contains(page, `<noscript><meta http-equiv="refresh" content="15">`) {
			t.Errorf("%s claims to be live but has no noscript refresh", path)
		}
	}
}

// TestUIEventStreamFailsSoftWithoutPush.
//
// No notifier configured means no stream, and the client must be told so plainly
// rather than handed a connection that never delivers — a silent empty stream
// looks live and never updates, which is the failure the timer exists to avoid
// being invisible.
func TestUIEventStreamFailsSoftWithoutPush(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	u.signInBrowser(t, true)

	resp := u.get(t, "/ui/events?network="+h.netID.String())
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 so the page stays on its timer", resp.StatusCode)
	}
}

// TestUIReserveHandsOutACodeOnce.
//
// The code is the deliverable, and it exists in exactly one HTTP response: the
// store keeps a peppered hash and cannot recover the original. no-store on the
// response is what stops the back button producing a second copy.
func TestUIReserveHandsOutACode(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	u.signInBrowser(t, true)

	formPage := body(t, u.get(t, "/ui/networks/"+h.netID.String()+"/hosts/new"))
	name := fmt.Sprintf("new-host-%s", uuid.NewString()[:8])

	resp := u.post(t, "/ui/networks/"+h.netID.String()+"/hosts", url.Values{
		"csrf_token": {csrfFrom(t, formPage)},
		"name":       {name},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reserve: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; an enrollment code must not survive a back button", got)
	}

	page := body(t, resp)
	if !strings.Contains(page, "Shown once") {
		t.Error("the handout does not say the code cannot be shown again")
	}
	// `join`, not `enroll`. A reservation is redeemed by a machine that has no
	// membership yet; printing the enroll command would fail on the machine, in
	// a way that reads as a broken code rather than a wrong instruction.
	if !strings.Contains(page, "orbit join") {
		t.Error("the handout does not include the command to run on the new machine")
	}

	// AND NO HOST EXISTS YET. This is the property the whole step turns on: the
	// membership is created when a machine redeems the code, so it names that
	// machine from the moment it exists. A row here would be the device-less
	// host that docs/model.md §5 invariant 1 forbids.
	ctx := context.Background()
	err := h.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.GetHostByName(ctx, h.netID, name)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reserving created a host before any machine arrived: %v", err)
	}
}

// TestUIReserveRefusesATakenName.
//
// This replaced a test that a lighthouse without a public address is refused.
// That field is no longer on the form: a reservation carries what an UNATTENDED
// machine must have decided for it — name, address, role — and lighthouse setup
// is done from the host page by an operator who is present. The API still
// refuses it, and e2e/admin_test.go still covers that.
//
// What matters on this form now is the name, because an unspent reservation
// holds one against the network. Two operators reserving "web-03" must not both
// walk away believing they have it.
func TestUIReserveRefusesATakenName(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	u.signInBrowser(t, true)

	name := "contested-" + uuid.NewString()[:8]
	formPage := body(t, u.get(t, "/ui/networks/"+h.netID.String()+"/hosts/new"))
	if resp := u.post(t, "/ui/networks/"+h.netID.String()+"/hosts", url.Values{
		"csrf_token": {csrfFrom(t, formPage)},
		"name":       {name},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("first reservation: %d", resp.StatusCode)
	}

	formPage = body(t, u.get(t, "/ui/networks/"+h.netID.String()+"/hosts/new"))
	resp := u.post(t, "/ui/networks/"+h.netID.String()+"/hosts", url.Values{
		"csrf_token": {csrfFrom(t, formPage)},
		"name":       {name},
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	page := body(t, resp)
	if !strings.Contains(page, "already taken") {
		t.Error("the refusal does not say what is wrong")
	}
	// The submission is handed back rather than discarded.
	if !strings.Contains(page, name) {
		t.Error("the form was cleared on refusal; the operator has to type it again")
	}
}

// TestUIRotationStateIsDerivedFromTheDatabase.
//
// The wizard's step is read off the CA rows every time. This adds a second CA
// and asserts the page moves without anything client-side having been told.
func TestUIRotationStateIsDerivedFromTheDatabase(t *testing.T) {
	h := setup(t)
	u := h.serveWeb(t)
	u.signInBrowser(t, true)

	before := body(t, u.get(t, "/ui/networks/"+h.netID.String()+"/rotation"))
	if !strings.Contains(before, "Create the replacement CA") {
		t.Fatal("the wizard does not name its first step")
	}
	// CA creation is deliberately not a control here: signer_ref names a path on
	// the server.
	if strings.Contains(before, `action="/ui/cas/new"`) || strings.Contains(before, "Create CA</button>") {
		t.Error("the UI offers CA creation; signer_ref names a location on the server")
	}
	if !strings.Contains(before, "orbit ca create") {
		t.Error("the wizard does not show the command that performs the step it will not do")
	}

	// Add a pending CA directly, as `orbit ca create` would.
	h.addCA(t, "rotation-target")

	after := body(t, u.get(t, "/ui/networks/"+h.netID.String()+"/rotation"))
	if !strings.Contains(after, "rotation-target") {
		t.Fatal("the new CA does not appear")
	}
	if !strings.Contains(after, "Promote to signer") {
		t.Error("a pending CA offers no promotion; the step did not advance")
	}
	if !strings.Contains(after, "pending") {
		t.Error("the CA's state is not stated in words")
	}
}

// TestUIEventStreamPushesAnEpochAdvance.
//
// The stream's contract is narrow on purpose: it says "an epoch moved, refetch"
// and carries no state. That is what lets the client stay a plain page refresh
// and keeps this channel from becoming a second, unversioned copy of what the
// page already renders.
//
// The complementary half — that convergence drifts with NO event, because
// last_seen_at and the applied epochs move on agent reports and RecordAgentReport
// issues no NOTIFY — is why app.js also runs a ten second timer. That timer is
// not an optimisation; without it a live page would sit still through exactly
// the change an operator is watching for.
func TestUIEventStreamPushesAnEpochAdvance(t *testing.T) {
	h := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notifier := notify.New(h.store.Pool(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { _ = notifier.Run(ctx) }()
	readyCtx, cancelReady := context.WithTimeout(ctx, 10*time.Second)
	defer cancelReady()
	if err := notifier.Ready(readyCtx); err != nil {
		t.Skipf("epoch notifier did not start: %v", err)
	}

	u := h.serveWebWith(t, notifier)
	u.signInBrowser(t, true)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		u.url+"/ui/events?network="+h.netID.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, c := range u.client.Jar.Cookies(mustParseURL(t, u.url)) {
		req.AddCookie(c)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		t.Fatalf("open the event stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("event stream: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q", ct)
	}
	// A cached event feed is worse than no feed.
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	// Advance an epoch the way any real change does.
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			_, err := tx.BumpEpoch(ctx, h.netID, store.EpochConfig)
			return err
		})
	}()

	deadline := time.Now().Add(15 * time.Second)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if time.Now().After(deadline) {
			t.Fatal("no epoch event arrived within the deadline")
		}
		if strings.HasPrefix(scanner.Text(), "event: epoch") {
			return // the contract, delivered
		}
	}
	t.Fatalf("the stream ended without an epoch event: %v", scanner.Err())
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
