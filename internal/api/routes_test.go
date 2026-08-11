package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These tests read the route table and assert the properties routes.go claims.
//
// They need no server, no database, and no nebula node, so they fail in
// milliseconds while someone is editing a route rather than at the end of an
// e2e run. e2e/overlay_test.go still checks surface isolation over live HTTP
// and should stay — it proves the listeners really are bound separately, which
// a table cannot.

func testRoutes(t *testing.T) *Server {
	t.Helper()
	// No store, no enroll service: nothing here dispatches a request, it only
	// reads how routes were declared.
	return New(nil, nil, Config{}, slog.New(slog.DiscardHandler))
}

// TestEveryAdminRouteDeclaresAScope is the one that matters.
//
// An admin route with no scope is authenticated but otherwise unrestricted: any
// token at all reaches it, including one minted for a CI job with hosts:read.
// On a surface that can create certificate authorities and mint certificates,
// that is not a small mistake, and nothing about it fails to compile.
func TestEveryAdminRouteDeclaresAScope(t *testing.T) {
	for _, r := range testRoutes(t).adminRoutes() {
		if r.scope != "" {
			continue
		}
		reason, ok := scopelessAdminRoutes[r.pattern]
		if !ok {
			t.Errorf("admin route %q declares no scope.\n"+
				"If that is deliberate, add it to scopelessAdminRoutes in routes.go\n"+
				"with the reason — every entry there needs one.", r.pattern)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("scopelessAdminRoutes[%q] has an empty reason", r.pattern)
		}
	}
}

// TestScopelessExceptionsAreStillRegistered keeps the exception list honest.
// A stale entry is how the list stops meaning anything: it accumulates routes
// that no longer exist, and the next reviewer assumes the one they are adding
// is equally fine.
func TestScopelessExceptionsAreStillRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, r := range testRoutes(t).adminRoutes() {
		registered[r.pattern] = true
	}
	for pattern := range scopelessAdminRoutes {
		if !registered[pattern] {
			t.Errorf("scopelessAdminRoutes lists %q, which is not a registered admin route", pattern)
		}
	}
}

// TestScopesAreKnown catches a typo. "memberships:raed" registers cleanly, is granted
// to nobody, and turns its route into one no token can reach — a 403 with no
// explanation and nothing to grep for.
func TestScopesAreKnown(t *testing.T) {
	for _, r := range testRoutes(t).adminRoutes() {
		if r.scope == "" {
			continue
		}
		if !knownScopes[r.scope] {
			t.Errorf("route %q requires scope %q, which is not in knownScopes.\n"+
				"Either it is a typo, or the scope is new and belongs in that map\n"+
				"and in the table in docs/design.md.", r.pattern, r.scope)
		}
	}
}

// TestSurfacesDoNotMix. Each surface has a distinct authentication model, so a
// route on the wrong one is authenticated by the wrong thing — or, on the
// public listener, by nothing.
func TestSurfacesDoNotMix(t *testing.T) {
	s := testRoutes(t)

	for _, tc := range []struct {
		name   string
		routes []route
		want   surface
		prefix string
	}{
		{"admin", s.adminRoutes(), surfaceAdmin, "/v1/"},
		{"agent", s.agentRoutes(), surfaceAgent, "/agent/v1/"},
		{"enroll", s.enrollRoutes(), surfaceEnroll, "/enroll/v1/"},
	} {
		for _, r := range tc.routes {
			if r.surface != tc.want {
				t.Errorf("%s route %q declares surface %q", tc.name, r.pattern, r.surface)
			}
			_, path, ok := strings.Cut(r.pattern, " ")
			if !ok {
				t.Errorf("route %q has no method; ServeMux would treat it as a path-only pattern "+
					"and accept every verb", r.pattern)
				continue
			}
			if !strings.HasPrefix(path, tc.prefix) {
				t.Errorf("%s route %q is not under %s — a path prefix is how the listeners "+
					"stay separable", tc.name, r.pattern, tc.prefix)
			}
		}
	}
}

// TestNoDuplicatePatterns. ServeMux panics on a duplicate at registration, so
// this would be caught eventually — but at process start, in production, rather
// than here. It also catches the same pattern appearing on two surfaces, which
// ServeMux would only notice on the combined dev Handler().
func TestNoDuplicatePatterns(t *testing.T) {
	s := testRoutes(t)
	seen := map[string]surface{}
	for _, r := range append(append(s.adminRoutes(), s.agentRoutes()...), s.enrollRoutes()...) {
		if prev, dup := seen[r.pattern]; dup {
			t.Errorf("pattern %q registered twice (%s and %s)", r.pattern, prev, r.surface)
		}
		seen[r.pattern] = r.surface
	}
}

// TestEveryRouteHasAHandler. A nil handler is a panic on the first request to
// that path — a 500 for one endpoint while the rest of the process looks fine,
// which is a bad way to find out.
func TestEveryRouteHasAHandler(t *testing.T) {
	s := testRoutes(t)
	for _, r := range append(append(s.adminRoutes(), s.agentRoutes()...), s.enrollRoutes()...) {
		if r.h == nil {
			t.Errorf("route %q has a nil handler", r.pattern)
		}
	}
}

// TestAdminRoutesAreNotReachableFromOtherSurfaces is the structural half of
// what e2e/overlay_test.go proves over the wire: building only the enroll and
// agent muxes must not produce any /v1/ admin path.
func TestAdminRoutesAreNotReachableFromOtherSurfaces(t *testing.T) {
	s := testRoutes(t)
	admin := map[string]bool{}
	for _, r := range s.adminRoutes() {
		admin[r.pattern] = true
	}
	for _, r := range append(s.agentRoutes(), s.enrollRoutes()...) {
		if admin[r.pattern] {
			t.Errorf("%q appears on both the admin surface and %s", r.pattern, r.surface)
		}
	}
}

// TestEveryAdminRouteRefusesAnUncredentialedRequest.
//
// The table records a scope; s.admin is what enforces it. Those are two
// different facts, and every test above checks only the first — so a route
// whose handler was registered WITHOUT the wrapper still declares its scope
// correctly and passes all of them, while answering anyone who asks.
//
// That is not hypothetical bookkeeping. There are two identical `a` helpers
// building admin routes, one in server.go and one in resources.go, each
// repeating `h: s.admin(scope, h)`. A third that forgets it, or an edit to one
// of the two, is a silent change from "scoped" to "public" that the route table
// would keep describing as scoped.
//
// Dispatching is safe without a store: a request carrying no credential is
// refused before anything is looked up.
func TestEveryAdminRouteRefusesAnUncredentialedRequest(t *testing.T) {
	s := testRoutes(t)

	checked := 0
	for _, r := range s.adminRoutes() {
		method, path, ok := strings.Cut(r.pattern, " ")
		if !ok {
			t.Fatalf("route %q has no method", r.pattern)
		}
		// Fill the wildcards; the value never matters because nothing should
		// get far enough to read it.
		for _, seg := range []string{"{ref}", "{id}", "{routeId}", "{addr}"} {
			path = strings.ReplaceAll(path, seg, "x")
		}
		if strings.ContainsAny(path, "{}") {
			t.Fatalf("route %q has a wildcard this test does not know how to fill", r.pattern)
		}

		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()

		// A handler that was NOT wrapped runs for real, and with no store that
		// ends in a nil dereference. Contain it per route: the panic is a
		// symptom of the same bug, and without this the first offender takes
		// the process down and hides every other one.
		func() {
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("%s reached its handler without a credential and panicked (%v). "+
						"It is registered without s.admin(scope, h).", r.pattern, v)
				}
			}()
			r.h.ServeHTTP(rec, req)
		}()

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s answered %d without a credential, want 401. "+
				"Its handler is probably registered without s.admin(scope, h).",
				r.pattern, rec.Code)
		}
		checked++
	}

	if checked < 40 {
		t.Fatalf("only %d admin routes dispatched; this test is not seeing the table", checked)
	}
}
