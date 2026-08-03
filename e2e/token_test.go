package e2e

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// TestRevokedTokenIsRejectedImmediately is the point of the whole endpoint.
//
// There is no cache to wait for and no epoch to converge: AuthenticateToken
// filters on revoked_at in the same query that resolves the token, so the very
// next request fails. If this ever needs a sleep to pass, authentication has
// grown a cache and a leaked token has become a timed problem.
func TestRevokedTokenIsRejectedImmediately(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "leaked-" + uuid.NewString()[:8], Scopes: []string{"hosts:read"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	if code := h.reqAs(t, tok.Token, http.MethodGet, ts.URL+"/v1/hosts?network_id="+h.netID.String(), nil, nil); code != http.StatusOK {
		t.Fatalf("fresh token = %d, want 200", code)
	}

	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/tokens/"+tok.ID, nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}

	if code := h.reqAs(t, tok.Token, http.MethodGet, ts.URL+"/v1/hosts?network_id="+h.netID.String(), nil, nil); code != http.StatusUnauthorized {
		t.Errorf("revoked token = %d, want 401", code)
	}
}

// TestRevokedTokenStaysListed. A revoked row that disappeared could not answer
// the question an incident actually asks: was it used, and was it used after we
// revoked it.
func TestRevokedTokenStaysListed(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	name := "audited-" + uuid.NewString()[:8]
	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: name, Scopes: []string{"hosts:read"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	// Use it, so last_used_at is set.
	h.reqAs(t, tok.Token, http.MethodGet, ts.URL+"/v1/hosts?network_id="+h.netID.String(), nil, nil)

	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/tokens/"+tok.ID, nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}

	var list []wire.TokenResponse
	if code := h.adminReq(t, http.MethodGet, ts.URL+"/v1/tokens", nil, &list); code != http.StatusOK {
		t.Fatalf("list tokens: %d", code)
	}

	var found *wire.TokenResponse
	for i := range list {
		if list[i].ID == tok.ID {
			found = &list[i]
		}
		if list[i].Token != "" {
			t.Fatalf("token %s leaked its plaintext in a listing", list[i].ID)
		}
	}
	if found == nil {
		t.Fatal("revoked token vanished from the listing")
	}
	if found.RevokedAt == "" {
		t.Error("listed token does not report revoked_at")
	}
	if found.LastUsedAt == "" {
		t.Error("listed token does not report last_used_at, which is the field " +
			"that answers whether a leaked token was used")
	}
}

// TestDoubleRevokeIsVisible. Revoking twice reports 404 rather than succeeding
// quietly, so an operator working through a leak can tell whether they are the
// one who revoked it.
func TestDoubleRevokeIsVisible(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "twice-" + uuid.NewString()[:8], Scopes: []string{"hosts:read"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/tokens/"+tok.ID, nil, nil); code != http.StatusNoContent {
		t.Fatalf("first revoke: %d", code)
	}
	if code := h.adminReq(t, http.MethodDelete, ts.URL+"/v1/tokens/"+tok.ID, nil, nil); code != http.StatusNotFound {
		t.Errorf("second revoke = %d, want 404", code)
	}
}

// TestTokenCanRevokeItself. Retiring the credential you are holding is what the
// last step of a rotation looks like; refusing it would make the most
// privileged token the one you cannot retire.
func TestTokenCanRevokeItself(t *testing.T) {
	h := setup(t)
	ts := h.servePublicOnly(t, freeUDPPort(t))

	var tok wire.TokenResponse
	if code := h.adminPost(t, ts.URL+"/v1/tokens", wire.CreateTokenRequest{
		Name: "self-" + uuid.NewString()[:8], Scopes: []string{"tokens:write"},
	}, &tok); code != http.StatusCreated {
		t.Fatalf("create token: %d", code)
	}

	if code := h.reqAs(t, tok.Token, http.MethodDelete, ts.URL+"/v1/tokens/"+tok.ID, nil, nil); code != http.StatusNoContent {
		t.Fatalf("self-revoke: %d", code)
	}
	// And it really is spent.
	if code := h.reqAs(t, tok.Token, http.MethodDelete, ts.URL+"/v1/tokens/"+tok.ID, nil, nil); code != http.StatusUnauthorized {
		t.Errorf("reuse after self-revoke = %d, want 401", code)
	}
}
