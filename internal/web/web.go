// Package web serves Orbit's operator UI.
//
// It is a fourth HTTP surface, alongside the three in internal/api, and it is
// separate for the same reason those three are separate from each other: a
// different threat model and a different exposure requirement. Specifically:
//
//   - It authenticates with a session COOKIE, and a cookie is attached by the
//     browser to every request to this origin whether or not the operator meant
//     to make it. That is the entire premise of CSRF, and it is a premise the
//     bearer-token surfaces do not have. Everything in middleware.go exists
//     because of it.
//   - It is mounted on its OWN listener (-ui-addr), never on the public enroll
//     listener and never on an overlay. A UI reachable only over the mesh is
//     unreachable during exactly the incident it exists for, and a UI on the
//     internet-facing enrollment port is a login form on the internet.
//
// The two credential systems are kept from leaking into each other in both
// directions: this surface REFUSES an Authorization: Bearer header outright
// (see rejectBearer), and /v1 never accepts the session cookie. Either leak
// would mean a stolen credential of one kind works on the other's surface, with
// the other's CSRF properties.
//
// # Architecture
//
// Server-rendered html/template over embed.FS. No SPA, no npm, no build step.
// docs/deployment.md sells "one VM, one binary, no node toolchain", and this
// process holds the mesh's root CA signing key: go.mod has six direct
// dependencies, and a frontend starter would pull several hundred transitive
// packages into the build of the thing that signs every identity on the mesh.
//
// EVERY SCREEN WORKS WITH JAVASCRIPT DISABLED. Forms are real
// <form method="post">, links are real links, and no action anywhere depends on
// a fetch(). static/app.js is roughly eighty lines of vanilla script for live
// refresh and a confirmation dialog; if it fails to load, every page still
// renders and every action still fires. That is what "used rarely, under
// pressure, possibly from a phone" actually requires.
//
// # Handlers call the store
//
// Not the JSON API over HTTP. These handlers run the same store and enroll
// functions internal/api's handlers run, with a *store.Identity resolved from
// the session instead of from a bearer token. A UI that proxied its own API
// would double every timeout, double every failure mode, and need a credential
// of its own to hold.
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/store"
)

//go:embed templates static
var assetFS embed.FS

// Sessions is the session layer this package needs, and the whole of it.
//
// An interface rather than a direct dependency on *store.Store for two reasons.
// It is the exact contract — nothing the UI does not use — so what this package
// requires of the session layer is readable in one place rather than inferred
// from call sites. And it lets every handler test run without a database, which
// is what makes "a broken template is a test failure rather than a 3am 500"
// affordable enough to actually enforce.
//
// StoreSessions, at the bottom of this file, is the only implementation that
// talks to Postgres.
type Sessions interface {
	// Create mints a session for an already-authenticated API token and returns
	// the cookie's plaintext value.
	Create(ctx context.Context, tokenID uuid.UUID, readOnly bool, ip *netip.Addr, userAgent string) (plaintext string, expiresAt time.Time, err error)

	// Resolve turns a cookie value into the same *store.Identity that
	// AuthenticateToken produces, so HasScope and Audit work unchanged.
	// store.ErrNotFound means unknown, expired, or revoked — never distinguished,
	// for the reason the API does not distinguish them either.
	Resolve(ctx context.Context, cookieValue string) (*store.Identity, error)

	// Revoke ends a session. Idempotent from the caller's point of view: logout
	// must not fail because the session was already gone.
	Revoke(ctx context.Context, cookieValue string) error

	// List returns the sessions that can reach the control plane right now,
	// with currentCookie's own row marked. Live only — see
	// store.ListUISessions for why a dead session is absent rather than greyed
	// out.
	List(ctx context.Context, currentCookie string) ([]store.UISession, error)

	// RevokeByID ends a session the caller picked out of List. Separate from
	// Revoke because an operator ending somebody else's browser does not have
	// its cookie, and there is no path from a listed session back to one.
	RevokeByID(ctx context.Context, id uuid.UUID, by store.Identity) error
}

// Config is what the UI needs from the process around it.
type Config struct {
	// BaseURL is the external URL the UI is reached at (-ui-url), used to build
	// absolute links and to check the Origin header on state-changing requests.
	// Empty means same-origin checks fall back to the request's Membership, which is
	// correct for the loopback default and wrong behind a proxy that rewrites it
	// — which is why binding non-loopback without this is refused at startup.
	BaseURL string

	// Notifier powers /ui/events. Nil disables push and the pages fall back to
	// their timer, which is slower but complete: see events.go for why the timer
	// exists even when push is up.
	Notifier *notify.Notifier

	// MaxStreams caps concurrent SSE connections across all networks. Zero means
	// DefaultMaxStreams. A browser tab left open on a wall display is a
	// connection held for weeks, and the pool behind it is the same one every
	// agent's renewal goes through.
	MaxStreams int
}

// DefaultMaxStreams bounds concurrent SSE connections.
//
// Deliberately small. This is an operator UI: the realistic ceiling is the
// number of people looking at it plus a couple of forgotten tabs, and a number
// in the thousands would only ever be reached by something that has gone wrong.
// Exceeding it fails soft — the page keeps its timer and keeps updating.
const DefaultMaxStreams = 64

// Server serves the UI.
type Server struct {
	store    *store.Store
	enroll   *enroll.Service
	sessions Sessions
	cfg      Config
	log      *slog.Logger

	tpl    *templates
	assets *assets

	// csrfKey salts the per-session CSRF token. Generated per process, and that
	// is a deliberate tradeoff documented at csrfToken.
	csrfKey []byte

	// loginLimit bounds sign-in attempts. See newLoginLimiter.
	loginLimit *api.Limiter

	// streams counts live SSE connections against Config.MaxStreams.
	streams atomic.Int64
}

func New(st *store.Store, es *enroll.Service, sess Sessions, cfg Config, log *slog.Logger) (*Server, error) {
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = DefaultMaxStreams
	}

	tpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	as, err := loadAssets()
	if err != nil {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return &Server{
		store: st, enroll: es, sessions: sess, cfg: cfg, log: log,
		tpl: tpl, assets: as, csrfKey: key, loginLimit: newLoginLimiter(),
	}, nil
}

// Routes mounts the UI on mux.
//
// Every route is under /ui/ so that a misconfiguration which mounts this on a
// shared mux cannot shadow /v1, /agent/v1, or /enroll/v1 — the paths are
// disjoint by construction rather than by review.
func (s *Server) Routes(mux *http.ServeMux) {
	// Assets first, and outside the session middleware entirely: a login page
	// that cannot fetch its own stylesheet because the operator is logged out is
	// a login page nobody can read. They are content-hashed public files with no
	// secrets in them.
	mux.Handle("GET /ui/static/", s.assets.handler())

	// Public: the login form and the login POST. Everything else requires a
	// session.
	mux.Handle("GET /ui/login", s.page(s.handleLoginForm))
	mux.Handle("POST /ui/login", s.page(s.handleLogin))
	// Logout takes no scope but does require a session, so that a POST from
	// another site cannot log an operator out mid-incident. It is state-changing,
	// so it is a POST and goes through the same CSRF checks as everything else.
	mux.Handle("POST /ui/logout", s.page(s.authed("", s.handleLogout)))

	get := func(pattern, scope string, h handlerFunc) {
		mux.Handle("GET "+pattern, s.page(s.authed(scope, h)))
	}
	post := func(pattern, scope string, h handlerFunc) {
		mux.Handle("POST "+pattern, s.page(s.authed(scope, h)))
	}

	get("/ui/{$}", "networks:read", s.handleIndex)
	get("/ui/networks", "networks:read", s.handleNetworks)
	get("/ui/networks/{id}", "networks:read", s.handleOverview)
	get("/ui/networks/{id}/convergence", "networks:read", s.handleConvergence)
	get("/ui/networks/{id}/hosts", "memberships:read", s.handleHostList)
	get("/ui/networks/{id}/hosts/new", "memberships:create", s.handleNewHostForm)
	post("/ui/networks/{id}/hosts", "memberships:create", s.handleReserveHost)
	get("/ui/networks/{id}/rotation", "cas:read", s.handleRotation)

	get("/ui/memberships/{id}", "memberships:read", s.handleHostDetail)
	get("/ui/memberships/{id}/block", "memberships:block", s.handleBlockConfirm)
	post("/ui/memberships/{id}/block", "memberships:block", s.handleBlock)
	post("/ui/memberships/{id}/unblock", "memberships:block", s.handleUnblock)
	post("/ui/memberships/{id}/enrollment-code", "memberships:enroll", s.handleEnrollmentCode)

	post("/ui/cas/{id}/activate", "cas:write", s.handleActivateCA)
	post("/ui/cas/{id}/retire", "cas:write", s.handleRetireCA)

	get("/ui/audit", "audit:read", s.handleAudit)
	get("/ui/tokens", "tokens:read", s.handleTokens)
	// Ending a session is scoped as tokens:write rather than as something of
	// its own, because a session is a reference to a token and revoking the
	// token already ends every session derived from it. Anyone who can do the
	// larger thing can do the smaller one; a separate scope would only be a
	// second place to get it wrong. A read-only session can see the list and
	// cannot act on it, which is the intended shape.
	post("/ui/sessions/{id}/revoke", "tokens:write", s.handleRevokeSession)

	// SSE. Its own scope is networks:read because that is what the events say
	// something about, and it revalidates the session inside the stream loop —
	// see events.go, where the reason a long-lived stream needs that is the point
	// of the whole file.
	mux.Handle("GET /ui/events", s.stream(s.authed("networks:read", s.handleEvents)))
}

// Handler returns the UI on a mux of its own, which is how orbitd mounts it:
// its own listener, its own timeouts.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.Routes(mux)
	return mux
}

//------------------------------------------------------------------------------
// Startup validation
//------------------------------------------------------------------------------

// NormalizeAddr fills in the host half of a -ui-addr.
//
// ":8081" and "8081" both become "127.0.0.1:8081". A bare port is what an
// operator types when they mean "on this machine", and net/http reads it as
// "on every interface" — which on a control plane holding the mesh's root CA key
// is the difference between a local UI and a login form on the internet. The
// default is loopback for the same reason -metrics-addr's is.
func NormalizeAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if !strings.Contains(addr, ":") {
		return "127.0.0.1:" + addr
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}

// CheckExposure refuses a UI bound where a browser cannot reach it safely.
//
// The session cookie is __Host- prefixed, which means Secure, which means a
// browser will not store it over plain http on a non-loopback origin. So a UI
// bound to 0.0.0.0 without an https:// front door is not merely riskier — the
// login does not work, and the failure presents as "the form just reloads",
// which is a terrible thing to debug during an incident.
//
// It is also the case that this listener carries every host name, every overlay
// address, and a Block button for the whole fleet, over a cleartext connection
// that anyone on the path can read and modify. Both facts are in the message,
// because an operator who reads only the first sentence should still stop.
func CheckExposure(addr, baseURL string) error {
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if isLoopbackHost(host) {
		return nil
	}
	if u, err := url.Parse(baseURL); err == nil && u.Scheme == "https" && u.Host != "" {
		return nil
	}
	return &ExposureError{Addr: addr, BaseURL: baseURL}
}

// ExposureError is the refusal to start a UI on a non-loopback address with no
// https:// front door.
type ExposureError struct {
	Addr    string
	BaseURL string
}

func (e *ExposureError) Error() string {
	return "-ui-addr " + e.Addr + " is not loopback and -ui-url is not an https:// URL.\n\n" +
		"The session cookie is __Host- prefixed and therefore Secure, so a browser " +
		"will not store it over plain http on this address: the login form will " +
		"appear to work and then silently return you to itself. And this listener " +
		"serves every host name, every overlay address, and a control that cuts a " +
		"host off the mesh — over a connection anyone on the path can read and " +
		"rewrite, on the machine holding the mesh's root CA signing key.\n\n" +
		"Put it behind TLS and pass -ui-url https://…, or bind it to 127.0.0.1 and " +
		"reach it over an SSH tunnel:\n\n" +
		"  ssh -N -L 8081:127.0.0.1:8081 orbit-control"
}

func isLoopbackHost(host string) bool {
	if host == "" {
		// A bare ":8081" that reached here without NormalizeAddr. Every
		// interface, which is the case this whole function exists to catch.
		return false
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		// A hostname that is not "localhost". It may well resolve to loopback,
		// but resolving it here would make startup depend on DNS and would
		// answer a question about this instant rather than about every future
		// one. Treated as exposed, which is the safe direction.
		return false
	}
	return a.IsLoopback()
}

// StoreSessions adapts a *store.Store to Sessions.
//
// It lives here rather than at the composition root so there is exactly one
// adapter. An adapter in cmd/orbitd cannot be reached by a test, so every test
// wanting a UI would write its own — and two implementations of one interface
// is how they come to disagree about something that matters.
func StoreSessions(st *store.Store) Sessions { return storeSessions{st} }

type storeSessions struct{ st *store.Store }

func (s storeSessions) Create(ctx context.Context, tokenID uuid.UUID, readOnly bool,
	ip *netip.Addr, userAgent string) (string, time.Time, error) {

	var (
		plaintext string
		expiresAt time.Time
	)
	err := s.st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		plaintext, expiresAt, err = tx.CreateUISession(ctx, tokenID, readOnly, ip, userAgent)
		return err
	})
	return plaintext, expiresAt, err
}

func (s storeSessions) Resolve(ctx context.Context, cookieValue string) (*store.Identity, error) {
	return s.st.ResolveSession(ctx, cookieValue)
}

func (s storeSessions) Revoke(ctx context.Context, cookieValue string) error {
	return s.st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RevokeUISession(ctx, cookieValue)
	})
}

func (s storeSessions) List(ctx context.Context, currentCookie string) ([]store.UISession, error) {
	var out []store.UISession
	err := s.st.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		out, err = tx.ListUISessions(ctx, currentCookie)
		return err
	})
	return out, err
}

func (s storeSessions) RevokeByID(ctx context.Context, id uuid.UUID, by store.Identity) error {
	return s.st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RevokeUISessionByID(ctx, id, by)
	})
}
