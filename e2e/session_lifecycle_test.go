package e2e

import (
	"context"
	"crypto/sha256"
	"net/http"
	"testing"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The consequences the reference-not-copy design is supposed to buy, exercised
// over live HTTP rather than argued for in a comment.

// TestRevokingATokenClosesTheBrowser is the whole point, end to end.
//
// An operator revokes a leaked token through the API they already use, and the
// browser session someone else has open dies on its next request. There is
// nothing else to do, nothing to remember, and no second list to clean up —
// which is precisely what a session storing its own scopes would have taken
// away, without any symptom.
func TestRevokingATokenClosesTheBrowser(t *testing.T) {
	h := setup(t)
	ts := h.serveBothSurfaces(t)
	ctx := context.Background()

	// A token of its own, so revoking it does not take the harness's bootstrap
	// credential with it.
	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "browser-" + t.Name(), Scopes: []string{"networks:read", "memberships:read", "memberships:block"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	sum := sha256.Sum256([]byte(tok.Token))
	id, err := h.store.AuthenticateToken(ctx, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	var cookie string
	if err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		cookie, _, err = tx.CreateUISession(ctx, id.TokenID, false, nil, "e2e-browser")
		return err
	}); err != nil {
		t.Fatalf("CreateUISession: %v", err)
	}

	if resp := browserReq(t, http.MethodGet, ts.URL+"/ui/networks", cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("the browser session does not work to begin with: %d", resp.StatusCode)
	}

	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/tokens/"+tok.ID, nil, nil); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("revoke token: %d", code)
	}

	// The next request. Not the next sweep, not the next poll.
	if resp := browserReq(t, http.MethodGet, ts.URL+"/ui/networks", cookie); !isLoginRedirect(resp) {
		t.Errorf("GET /ui/networks after revoking the session's token = %d (Location %q); "+
			"want the login redirect.\nThe session is holding a credential that no "+
			"longer exists, and the browser must be told to sign in again rather "+
			"than shown a page.", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// TestReadOnlySessionCannotBlockAHost. The narrowing is the highest-value
// mitigation available here, and this is what it buys: a phone looking at
// convergence cannot cut a host off, even though the token behind it can.
func TestReadOnlySessionCannotBlockAHost(t *testing.T) {
	h := setup(t)
	ts := h.serveBothSurfaces(t)

	readOnly := h.signIn(t, true)
	full := h.signIn(t, false)

	// Straight into the store, because this harness mounts no enroll service and
	// every route that brings a membership into existence now goes through one:
	// a reservation is minted by it and redeemed by it. The block confirmation
	// page only needs a host record to describe, and what is under test is the
	// scope check on that page, not how the row got there.
	host := h.insertHost(t, "narrowed", "10.42.14.1")

	// The BLOCK CONFIRMATION page, deliberately: it is a GET, so no CSRF token
	// is involved and the only thing that can refuse it is the scope check —
	// which is what this test is about. Probing with the POST would conflate
	// "narrowed" with "no CSRF token", and the two have very different fixes.
	blockPage := ts.URL + "/ui/memberships/" + host.ID + "/block"

	// Both sessions come from the same "*" bootstrap token, so any difference
	// between them is the narrowing and nothing else.
	if resp := browserReq(t, http.MethodGet, ts.URL+"/ui/memberships/"+host.ID, readOnly); resp.StatusCode != http.StatusOK {
		t.Errorf("a read-only session cannot read a host: %d", resp.StatusCode)
	}
	if resp := browserReq(t, http.MethodGet, blockPage, readOnly); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a read-only session reached a memberships:block route = %d, want 403.\n"+
			"Its token holds \"*\"; narrowing is the only thing that should stop it.",
			resp.StatusCode)
	}
	if resp := browserReq(t, http.MethodGet, blockPage, full); resp.StatusCode != http.StatusOK {
		t.Errorf("the opt-out session cannot reach the block page either (%d); read-only "+
			"would then not be a choice, and an operator responding to an incident "+
			"has no path", resp.StatusCode)
	}
}

// TestSignOutEndsTheSessionAndNotTheToken. Signing out of a console must not
// break the shell the same operator has open, or nobody will sign out.
func TestSignOutEndsTheSessionAndNotTheToken(t *testing.T) {
	h := setup(t)
	ts := h.serveBothSurfaces(t)
	ctx := context.Background()

	cookie := h.signIn(t, false)
	if resp := browserReq(t, http.MethodGet, ts.URL+"/ui/networks", cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("session does not work: %d", resp.StatusCode)
	}

	if err := h.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RevokeUISession(ctx, cookie)
	}); err != nil {
		t.Fatalf("RevokeUISession: %v", err)
	}

	// Redirected to the login page, not 401: this is a console, and a browser
	// shown a bare 401 sees a blank screen with no way forward.
	if resp := browserReq(t, http.MethodGet, ts.URL+"/ui/networks", cookie); !isLoginRedirect(resp) {
		t.Errorf("GET /ui/networks after sign-out = %d (Location %q), want a redirect to the login page",
			resp.StatusCode, resp.Header.Get("Location"))
	}
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/memberships?network_id="+h.netID.String(), nil, nil); code != http.StatusOK {
		t.Errorf("signing out of the browser broke the bearer token: /v1/memberships = %d", code)
	}
}

// TestNoCookieIsUnauthorizedNotAServerError. The unauthenticated case is the
// one every visitor hits first, and a 500 there would be both alarming and a
// small information leak.
func TestNoCookieIsUnauthorizedNotAServerError(t *testing.T) {
	h := setup(t)
	ts := h.serveBothSurfaces(t)

	for _, cookie := range []string{"", "orbses_not-a-real-session-value-at-all"} {
		resp := browserReq(t, http.MethodGet, ts.URL+"/ui/networks", cookie)
		if !isLoginRedirect(resp) {
			t.Errorf("GET /ui/networks with cookie %q = %d (Location %q), want a redirect to the login page",
				cookie, resp.StatusCode, resp.Header.Get("Location"))
		}
		// And specifically not a 5xx: the unauthenticated case is the one every
		// visitor hits first, and a 500 there is both alarming and a small leak.
		if resp.StatusCode >= 500 {
			t.Errorf("GET /ui/networks with cookie %q = %d; an absent session is not a server error",
				cookie, resp.StatusCode)
		}
	}
}
