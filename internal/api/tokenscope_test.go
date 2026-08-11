package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/store"
)

// callCreateToken dispatches the handler as a caller holding exactly these
// scopes, and reports whether it got past the checks.
//
// No store is needed, and that is the assertion rather than a convenience: a
// refusal must happen before anything is written. A request that IS allowed
// through reaches the nil store and panics, which is what "reachedStore" means
// — recovered here so each test can say what it expects instead of failing as
// a stack trace.
func callCreateToken(t *testing.T, held []string, body string) (rec *httptest.ResponseRecorder, reachedStore bool) {
	t.Helper()
	s := New(nil, nil, Config{}, slog.New(slog.DiscardHandler))

	req := httptest.NewRequest(http.MethodPost, "/v1/tokens", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), identityKey{},
		&store.Identity{Kind: "token", Subject: "t", Display: "test", Scopes: held}))

	rec = httptest.NewRecorder()
	func() {
		defer func() {
			if recover() != nil {
				reachedStore = true
			}
		}()
		s.handleCreateToken(rec, req)
	}()
	return rec, reachedStore
}

// TestATokenCannotMintAStrongerToken.
//
// req.Scopes went from the request body into the database unread. Nothing
// checked that the caller held what it was granting, so tokens:write was the
// only scope that mattered on this API: a CI credential allowed to rotate its
// own key could ask for "*" and get it, and every scope the table separates so
// carefully — cas:write, memberships:block, policy:write — was one request away
// from any token that could manage tokens at all.
func TestATokenCannotMintAStrongerToken(t *testing.T) {
	for _, want := range []string{"*", "cas:write"} {
		rec, reached := callCreateToken(t, []string{"tokens:write"},
			`{"name":"esc","scopes":["`+want+`"]}`)
		if reached {
			t.Errorf("granting %q from a tokens:write credential was written to the store", want)
			continue
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("granting %q from a tokens:write credential answered %d, want 403", want, rec.Code)
		}
	}
}

// TestAWildcardTokenStillGrantsAnything. The rule is "no stronger than
// yourself", not "no wildcards" — an operator's "*" token has to keep working
// or the fix above is a regression dressed as a hardening.
func TestAWildcardTokenStillGrantsAnything(t *testing.T) {
	rec, reached := callCreateToken(t, []string{"*"}, `{"name":"ok","scopes":["cas:write","*"]}`)
	if !reached {
		t.Errorf("a \"*\" token was refused with %d before it could grant anything", rec.Code)
	}
}

// TestAMistypedScopeIsRefused.
//
// knownScopes says in its own comment that listing scopes rather than inferring
// them is what makes "memberships:raed" a test failure instead of "a 403 with no
// explanation and nothing to grep for". It was consulted by the route table and
// by tests, and never by the endpoint where a human types one.
func TestAMistypedScopeIsRefused(t *testing.T) {
	rec, reached := callCreateToken(t, []string{"*"}, `{"name":"typo","scopes":["memberships:raed"]}`)
	if reached {
		t.Fatal("a mistyped scope was written to the store")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a mistyped scope answered %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "memberships:raed") {
		t.Errorf("the error does not name the offending scope: %s", rec.Body.String())
	}
}
