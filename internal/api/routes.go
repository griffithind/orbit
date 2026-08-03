package api

import (
	"net/http"
	"slices"
	"strings"
)

// The route table.
//
// Registration used to be thirty-three mux.Handle calls spread across two
// files, which works and is perfectly readable — but it leaves one class of
// mistake completely unguarded. Orbit runs three surfaces with three different
// authentication models on three separately-bound listeners, and with a plain
// ServeMux a route registered against the wrong mux silently inherits the wrong
// middleware. An admin route mounted on the agent listener is authenticated by
// source address; an agent route mounted on the public one is not authenticated
// at all. Nothing about either mistake fails to compile, and nothing about
// either looks wrong in a diff.
//
// Making the routes data means a test can read them. That is the whole purpose:
// see routes_test.go, which asserts every property this comment claims.
//
// e2e/overlay_test.go already checks surface isolation by issuing live HTTP
// requests against a running server, and it should stay — it proves the
// listeners really are separate, which a table cannot. This proves the
// registration is right without needing a server, a database, or a nebula node,
// so it fails in milliseconds during development rather than at the end of a
// 25-second e2e run.

// surface is which listener a route belongs on. The three authenticated ones
// have different threat models (see the package doc) and must never be mixed;
// surfaceHealth is separate again and explains itself below.
type surface string

const (
	surfaceEnroll surface = "enroll" // public, unauthenticated but credential-gated
	surfaceAgent  surface = "agent"  // overlay only, identity from source address
	surfaceAdmin  surface = "admin"  // scoped bearer tokens

	// surfaceHealth is the probe surface: /healthz and /readyz, no credential of
	// any kind.
	//
	// A fourth surface rather than a corner of an existing one, for two reasons.
	// Its threat model is the only one that is literally "anyone who can open
	// the socket" — the other three each authenticate something, and a route
	// that authenticates nothing does not belong in a list whose invariant is
	// that they all do. And it is the only surface mounted on more than one
	// listener: the same two paths go on the public listener and on each overlay
	// listener (Server.HealthRoutes says why), which the per-surface path prefix
	// rule cannot express.
	//
	// The tradeoff: routes_test.go does not walk this surface, because the two
	// rules it enforces — declare a known scope, live under the surface's prefix
	// — are exactly the two rules that do not apply here. The properties that do
	// apply are asserted over live HTTP in e2e/ops_health_test.go: neither path
	// takes a token, both are absent from nothing, and readiness fails while
	// liveness passes when Postgres is gone.
	surfaceHealth surface = "health"

	// surfaceUI is the browser console: session cookies, and never a bearer
	// token. Its routes are registered by internal/web on its own mux, so none
	// of them appear in this table — but the surface is named here because this
	// is where the surface model is written down, and a fifth authentication
	// model that is documented nowhere is how the fourth one gets mixed into
	// the third.
	//
	// THE RULE THAT MATTERS, and the one this const exists to record:
	//
	//	/v1 MUST NEVER ACCEPT THE COOKIE, AND THE UI SURFACE MUST NEVER ACCEPT
	//	A BEARER TOKEN.
	//
	// Every /v1 route was written assuming bearer authentication, which a
	// browser cannot be made to send cross-site — so none of them carry CSRF
	// defences, and several would be dangerous without one. DELETE
	// /v1/hosts/{id} takes its reason from a QUERY PARAMETER: honouring a
	// cookie there turns a link into a host decommission. The isolation is
	// structural rather than a check inside a handler — Server.admin is built
	// from bearerCredential and Server.UI from sessionCredential, and neither
	// has a path to the other's credential — and e2e/session_isolation_test.go
	// asserts both directions over live HTTP, as overlay_test.go does for the
	// agent surface.
	surfaceUI surface = "ui"
)

// route is one endpoint.
type route struct {
	// pattern is the ServeMux pattern, method included: "GET /v1/hosts/{id}".
	pattern string
	surface surface

	// scope is the token scope an admin route requires. Empty means
	// authenticated-only, which is a deliberate choice on exactly one route and
	// a bug anywhere else — routes_test.go enforces that.
	//
	// Meaningless on the enroll and agent surfaces, which do not use tokens.
	scope string

	h http.Handler
}

// knownScopes is every scope the API recognises.
//
// Listed rather than inferred so a typo is a test failure. "hosts:raed" would
// otherwise register cleanly, be granted to nobody, and turn its route into one
// that no token can reach — a 403 with no explanation and nothing to grep for.
var knownScopes = map[string]bool{
	"hosts:create": true, "hosts:read": true, "hosts:write": true,
	"hosts:block": true, "hosts:enroll": true,
	"networks:read": true, "networks:write": true,
	"roles:read": true, "roles:write": true,
	"cas:read": true, "cas:write": true,
	"tokens:read": true, "tokens:write": true,
	"audit:read": true,

	// The network policy document gets its own pair rather than reusing
	// networks:*, for the reason the trust bundle takes cas:read instead of
	// networks:read: the scope should bound what a token can DO, not which noun
	// it names. This document IS the firewall for every host in the network, so
	// a credential trusted to rename a network or add a prefix must not reach it
	// through the same grant.
	//
	// policy:write also gates the firewall_source switch on PATCH
	// /v1/networks/{ref}, which the route table declares as networks:write.
	// That route needs BOTH, and the handler checks the second — see
	// handleUpdateNetwork. The table cannot express a per-field scope, and
	// splitting the network PATCH in two to make it expressible would put the
	// only place a network's posture is set in two places.
	"policy:read": true, "policy:write": true,
}

// ReadOnlyScopes returns the read half of knownScopes, sorted.
//
// This is what a read-only browser session on a "*" token is narrowed to.
// store.narrowToReadOnly has to carry its own copy of the list — store cannot
// import api, and expanding "*" is the one case an intersection cannot be
// written without enumerating the set — so this function exists to make the
// duplication checkable. internal/store/session_test.go asserts the two agree,
// which turns "a scope was added in one place and not the other" into a test
// failure rather than a scope a read-only session silently never gets.
func ReadOnlyScopes() []string {
	out := make([]string, 0, len(knownScopes))
	for s := range knownScopes {
		if strings.HasSuffix(s, ":read") {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// scopelessAdminRoutes are the admin routes that require authentication but no
// scope. Each needs a reason, and there is currently exactly one.
//
// /v1/whoami describes the caller to itself, which reveals nothing the caller
// does not already hold. Gating it would make the one request a credential with
// unknown scopes can usefully make the one it might be refused — and the
// break-glass check in docs/deployment.md 5 depends on exactly that.
var scopelessAdminRoutes = map[string]string{
	"GET /v1/whoami": "describes the caller to itself; reveals nothing it does not hold",
}

func register(mux *http.ServeMux, routes []route) {
	for _, r := range routes {
		mux.Handle(r.pattern, r.h)
	}
}
