package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/store"
)

// SessionCookie is the name of the session cookie.
//
// Taken from internal/api rather than declared here, so the surface that SETS
// the cookie and the surface that must REFUSE it cannot come to disagree about
// what it is called. A drift there would be silent and total: /v1's refusal
// would be checking for a cookie this package never sets, and the isolation test
// asserting that refusal would keep passing.
//
// The __Host- prefix is not decoration. A browser refuses to store a cookie with
// this prefix unless it is Secure, Path=/, and carries NO Domain attribute — and
// that last clause is the one that matters. Without it, anything that can set a
// cookie on a sibling hostname (a stray subdomain, a takeover of one, a
// forgotten staging box) can plant a cookie that this origin will accept and
// that this server cannot distinguish from one it issued.
const SessionCookie = api.SessionCookieName

// csrfField is the hidden input every state-changing form carries.
const csrfField = "csrf_token"

type handlerFunc func(http.ResponseWriter, *http.Request) error

// page wraps an HTML handler with everything this surface requires of every
// request that is not a static asset.
//
// The order is the argument. Outermost runs first on the way in:
//
//  1. securityHeaders, so that even a 400 from a later layer carries the CSP and
//     the no-store. An error page without them is still an HTML page rendering
//     content, and it is exactly the page nobody remembers to check.
//  2. rejectBearer, before authentication, so that presenting an API token here
//     is refused rather than quietly ignored. See below.
//  3. crossOrigin, before the handler does anything, because a CSRF check that
//     runs after the mutation is not a check.
//  4. errors, which turns a returned error into a rendered page rather than a
//     bare status.
func (s *Server) page(h handlerFunc) http.Handler {
	// The innermost layer is where a handlerFunc becomes an http.Handler: every
	// error a handler returns has been rendered by errorPage before it gets
	// here, so there is nothing left to report upward.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = s.errorPage(h)(w, r)
	})
	return s.securityHeaders(s.rejectBearer(s.crossOrigin(inner)))
}

// stream is page without the HTML caching rules, for SSE.
//
// text/event-stream needs no-store just as much (an event feed replayed from a
// cache is worse than no feed), but it must not get the CSP-and-frame headers
// meant for documents, and it must not be wrapped in an error renderer that
// would emit HTML into an event stream.
func (s *Server) stream(h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !s.checkBearer(w, r) {
			return
		}
		if err := h(w, r); err != nil {
			// The stream is either already open, in which case the status is on
			// the wire and there is nothing to say, or it never opened, in which
			// case handleEvents has already written its own status.
			s.log.Debug("ui event stream ended", "error", err)
		}
	})
}

//------------------------------------------------------------------------------
// Headers
//------------------------------------------------------------------------------

// contentSecurityPolicy is the CSP served on every HTML response.
//
// default-src 'none' and then an allowance per directive that is actually used,
// rather than a permissive default narrowed by exceptions: the difference shows
// up when someone adds a feature that reaches for a new fetch destination, and
// the strict form fails visibly in development instead of silently permitting it
// in production.
//
// THERE IS NO 'unsafe-inline', anywhere, which is why there is not one inline
// <script> or style="" attribute in the templates. That constraint is the whole
// value: with it, a stored value that escapes html/template's contextual
// escaping still cannot execute, because the only scripts the browser will run
// are the ones served from this origin as files. Without it, the CSP is a
// comment.
//
// form-action 'self' matters more here than it looks: every destructive action
// in this UI is a form POST, and this is what stops an injected <form> from
// aiming one at somebody else's server.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self'; " +
	"connect-src 'self'; " +
	"form-action 'self'; " +
	"base-uri 'none'; " +
	"frame-ancestors 'none'"

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")

		// no-referrer, not the usual same-origin default. A UI path carries a
		// host uuid and a network uuid, and the one link an operator clicks out
		// of an incident page is the one to a vendor's status page.
		h.Set("Referrer-Policy", "no-referrer")

		// frame-ancestors already covers modern browsers; this is for the ones
		// that do not implement it, and it costs a header.
		h.Set("X-Frame-Options", "DENY")

		// no-store on every HTML response, not no-cache. Two pages in this UI
		// render a secret exactly once — an enrollment code and, if tokens grow a
		// create form, a new token — and no-cache still permits the browser to
		// keep the bytes and re-render them on the back button. no-store is the
		// only value that says "do not write this down".
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")

		next.ServeHTTP(w, r)
	})
}

//------------------------------------------------------------------------------
// The two credential systems must not meet
//------------------------------------------------------------------------------

// rejectBearer refuses any request to the UI carrying an Authorization: Bearer
// header.
//
// Refused, not ignored, and the distinction is the point. If this surface merely
// ignored the header, an operator or a script could hold an API token, aim it at
// /ui, get a login redirect, and reasonably conclude the UI "does not support
// tokens". What actually happened is subtler and worse: the request was served
// under whatever session cookie the browser attached, which during an incident
// may be a colleague's. Every action taken would be audited as them.
//
// It also closes the mirror image of the rule internal/api enforces — /v1 never
// accepts the session cookie. Together the two mean a credential is usable on
// exactly the surface whose CSRF properties it was designed for. A bearer token
// is safe on /v1 because a browser never attaches it automatically; a cookie is
// safe here because everything in this file assumes it does.
func (s *Server) rejectBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.checkBearer(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) checkBearer(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return true
	}
	// Any Authorization header, not only Bearer. Basic, Negotiate, or a scheme
	// nobody here has heard of are all the same mistake: a credential aimed at
	// the wrong surface. Naming Bearer in the message covers the case that
	// actually happens.
	s.writeStatus(w, r, http.StatusBadRequest,
		"the operator UI does not accept Authorization headers",
		"This surface authenticates with a session cookie, and API tokens belong to "+
			"the JSON API on /v1. If it ignored this header the request would have been "+
			"served under whatever session your browser attached instead — possibly "+
			"someone else's — and audited as them.\n\n"+
			"For scripting, use /v1 with the same token:\n\n"+
			"  curl -H \"Authorization: Bearer $ORBIT_TOKEN\" "+s.origin(r)+"/v1/memberships?network_id=…\n\n"+
			"(the JSON API is on the -addr listener, not this one)")
	return false
}

//------------------------------------------------------------------------------
// CSRF
//------------------------------------------------------------------------------

// crossOrigin rejects state-changing requests that did not originate here.
//
// THREE INDEPENDENT LAYERS, because each one has a gap the others cover:
//
//  1. SameSite=Lax on the cookie (see setSessionCookie). The browser simply does
//     not attach the session to a cross-site POST, so the request arrives
//     unauthenticated. This is the strongest layer and it needs no server code —
//     but it is the browser's promise, not ours, and it is Lax rather than
//     Strict for a reason given at the cookie.
//
//  2. http.NewCrossOriginProtection, from the standard library as of Go 1.25.
//     Checks Sec-Fetch-Site, falling back to comparing Origin against Membership. Used
//     rather than reimplemented because the fallback rules are fiddly and being
//     subtly wrong here is invisible until it matters.
//
//  3. A per-session token in every form. This is the layer that does not depend
//     on the browser sending anything in particular, and it is what still holds
//     if a future browser bug, an extension, or a proxy strips Sec-Fetch-Site and
//     Origin — which is exactly the case the stdlib check allows through, since
//     it must not break non-browser clients.
//
// Layer 2 is deliberately tightened: a request with NEITHER Sec-Fetch-Site NOR
// Origin is allowed by the stdlib (it assumes a non-browser client) and is
// refused here. Nothing that legitimately POSTs to this surface is a non-browser
// client — that is what /v1 is for — so the case the stdlib keeps working is a
// case this surface does not have, and leaving it open only preserves the one
// shape a CSRF attempt could take if it found a way to suppress both headers.
func (s *Server) crossOrigin(next http.Handler) http.Handler {
	// One instance, built once: it holds the trusted-origin set.
	prot := http.NewCrossOriginProtection()
	if s.cfg.BaseURL != "" {
		// Behind a TLS terminator the Membership the handler sees may not be the host
		// the browser used. Naming the external origin makes the Origin
		// comparison compare against the truth rather than against whatever the
		// proxy forwarded.
		if u, err := url.Parse(s.cfg.BaseURL); err == nil && u.Scheme != "" && u.Host != "" {
			// An error here is a malformed -ui-url, which CheckExposure has
			// already had a chance to reject; ignoring it leaves the strict
			// same-Membership comparison in force, which is the safe direction.
			_ = prot.AddTrustedOrigin(u.Scheme + "://" + u.Host)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}

		if err := prot.Check(r); err != nil {
			s.refuseCrossOrigin(w, r, err.Error())
			return
		}
		// The tightening described above.
		if r.Header.Get("Sec-Fetch-Site") == "" && r.Header.Get("Origin") == "" {
			s.refuseCrossOrigin(w, r,
				"the request carried neither Sec-Fetch-Site nor Origin, so its origin "+
					"cannot be established")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// safeMethod reports whether a method is one this surface guarantees changes
// nothing. Every handler behind a GET here is a read; that is the contract the
// CSRF check depends on, and it is why there is no /ui/memberships/{id}/block?do=1.
func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func (s *Server) refuseCrossOrigin(w http.ResponseWriter, r *http.Request, detail string) {
	s.log.Warn("ui refused a cross-origin state-changing request",
		"path", r.URL.Path, "origin", r.Header.Get("Origin"),
		"secFetchSite", r.Header.Get("Sec-Fetch-Site"), "detail", detail)
	s.writeStatus(w, r, http.StatusForbidden, "cross-origin request refused",
		"This action can only be started from a page served by this UI. "+detail+".\n\n"+
			"If you reached this by following a link from a chat message or a ticket, "+
			"open the UI first and navigate to the host from there.")
}

// signNotice returns the query parameters carrying a server-authored banner.
//
// The banner text used to ride in ?notice= and be rendered on trust. It is
// server-authored at every call site, and newPage did not enforce that — so
// anyone could send an operator a link to the real origin, with real TLS, and
// choose what the page said. On /ui/login, which is where a 256-bit admin token
// is typed and where the read-only default can be talked out of, that is a
// convincing thing to be able to do. Not XSS: the value goes through
// html/template into a text node and the CSP has no unsafe-inline. Content
// spoofing is enough.
//
// An allowlist of known messages does not fit, because the real ones carry
// runtime data — which host, which epoch. So the message is signed instead, with
// the same deployment-wide key as the form token. Every replica derives that key
// from the KEK, so a notice written by one verifies on another; before that key
// was shared this would have broken behind a load balancer.
func (s *Server) signNotice(msg string) url.Values {
	return url.Values{"notice": {msg}, "notice_sig": {s.noticeMAC(msg)}}
}

// verifiedNotice returns the banner only when this deployment wrote it.
func (s *Server) verifiedNotice(r *http.Request) string {
	msg := r.URL.Query().Get("notice")
	if msg == "" {
		return ""
	}
	want := s.noticeMAC(msg)
	got := r.URL.Query().Get("notice_sig")
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return ""
	}
	return msg
}

// noticeMAC is domain-separated from the form token so a value that works as
// one is not usable as the other.
func (s *Server) noticeMAC(msg string) string {
	m := hmac.New(sha256.New, s.csrfKey)
	m.Write([]byte("orbit ui notice v1\x00"))
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// csrfToken derives a form token from the session cookie value.
//
// Derived rather than stored, which removes an entire table and, more usefully,
// removes the failure where a form breaks because its token expired
// independently of the session it belongs to.
//
// HMAC over the cookie value with a per-process key. The key being per-process
// means a restart invalidates every open form, and that is the deliberate half
// of the tradeoff: the alternative — a fixed derivation from the cookie value
// alone — survives restarts but makes the token computable by anyone who learns
// the cookie value, which collapses the third layer into the first. A restart
// costs one re-submit, with a page that says so; the other way costs the layer.
func (s *Server) csrfToken(cookieValue string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	// A label, so this key can never be reused for a second purpose and produce
	// a token valid in both.
	mac.Write([]byte("orbit-ui-csrf\x00"))
	mac.Write([]byte(cookieValue))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// checkCSRFToken verifies the hidden form field.
func (s *Server) checkCSRFToken(r *http.Request) bool {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return false
	}
	want := s.csrfToken(c.Value)
	got := r.PostFormValue(csrfField)
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

//------------------------------------------------------------------------------
// Authentication
//------------------------------------------------------------------------------

type ctxKey int

const (
	identityKey ctxKey = iota
	cookieKey
)

func identityFrom(ctx context.Context) *store.Identity {
	id, _ := ctx.Value(identityKey).(*store.Identity)
	return id
}

func cookieFrom(ctx context.Context) string {
	v, _ := ctx.Value(cookieKey).(string)
	return v
}

// authed resolves the session and checks a scope.
//
// The scope names are the same ones internal/api's routes declare, checked with
// the same Identity.HasScope, because they are the same permission. A token that
// cannot block a host through /v1 must not be able to block one by logging into
// the UI with it, and the only way to guarantee that is to not have a second
// authorization model.
func (s *Server) authed(scope string, h handlerFunc) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		c, err := r.Cookie(SessionCookie)
		if err != nil || c.Value == "" {
			return s.needLogin(w, r, "")
		}

		id, err := s.sessions.Resolve(r.Context(), c.Value)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Unknown, expired, and revoked are one answer, as they are on
				// every other credential in this system. Clear the cookie so the
				// browser stops sending a value that will never work again.
				clearSessionCookie(w)
				return s.needLogin(w, r,
					"Your session has ended. Sign in again.")
			}
			return err
		}

		// The form token, checked after the session resolves so that an expired
		// session reads as "sign in again" rather than as a CSRF failure — during
		// an incident those two messages send an operator to very different
		// places.
		if !safeMethod(r.Method) && !s.checkCSRFToken(r) {
			s.log.Warn("ui refused a request with a bad form token",
				"path", r.URL.Path, "actor", id.Display)
			s.writeStatus(w, r, http.StatusForbidden, "this form has expired",
				"The form's one-time token did not match this session. That happens "+
					"when the control plane restarted while the page was open, or when "+
					"the page was left open across a sign-out.\n\n"+
					"Reload the page and try again — nothing was changed.")
			return nil
		}

		if scope != "" && !id.HasScope(scope) {
			s.writeStatus(w, r, http.StatusForbidden, "this token lacks "+scope,
				"You are signed in as "+id.Display+", whose token does not carry the "+
					scope+" scope. Sign in with a credential that does, or ask for the "+
					"scope to be granted:\n\n  orbit token create -name … -scopes "+scope)
			return nil
		}

		ctx := context.WithValue(r.Context(), identityKey, id)
		ctx = context.WithValue(ctx, cookieKey, c.Value)
		return h(w, r.WithContext(ctx))
	}
}

// needLogin sends an unauthenticated request to the login form.
//
// A redirect rather than a 401, and it carries ?next=. The link an operator
// follows during an incident comes from Slack or from a pager, points at a host
// detail page, and lands here; without ?next= they arrive at an overview and
// have to find the host again by hand, which is the moment a UI stops being
// faster than the CLI.
func (s *Server) needLogin(w http.ResponseWriter, r *http.Request, note string) error {
	if r.Method != http.MethodGet {
		// A POST cannot be replayed after login — the form body is gone — so
		// bouncing it through a redirect would silently drop the action. Say so.
		s.writeStatus(w, r, http.StatusUnauthorized, "your session has ended",
			"This action was not performed. Sign in again and repeat it.")
		return nil
	}

	q := url.Values{}
	if next := r.URL.RequestURI(); next != "" && next != "/ui/login" {
		q.Set("next", next)
	}
	if note != "" {
		q.Set("note", note)
	}
	http.Redirect(w, r, "/ui/login?"+q.Encode(), http.StatusSeeOther)
	return nil
}

//------------------------------------------------------------------------------
// The session cookie
//------------------------------------------------------------------------------

// setSessionCookie writes the session cookie.
//
// This package is the only thing that writes it, and that is worth keeping: two
// implementations of a security-critical thing, disagreeing on a security
// property, is worse than either alone, because a reader finds whichever comes
// first.
//
// SameSite is Lax rather than Strict. Strict would be the stronger default, and
// the case against Lax is real — it is only safe for a UI that never mutates
// behind a GET, which is a promise about handlers not yet written. This package
// makes that promise enforceable instead of aspirational: every route is
// registered by method in Routes, safeMethod defines what may be reached
// without a CSRF check, and TestSafeMethods and TestEveryActionIsARealForm fail
// if a mutation ever appears behind a GET. Lax is what keeps a link from a
// ticket or from chat landing signed in rather than on a login page, which is
// the moment an operator is least able to absorb one.
//
// SameSite=Lax, and NOT Strict, is therefore the deliberate choice here. With
// Strict, a top-level navigation that
// originated anywhere else — a link in a Slack thread, a link in a PagerDuty
// alert, a link in the ticket that opened the incident — arrives without the
// cookie, and the operator lands on a login page. What that reads as, at 3am, is
// "I am locked out", and the next five minutes go to credentials instead of to
// the outage. Lax attaches the cookie to exactly that case (top-level GET) and
// to nothing else: a cross-site POST, which is the shape every CSRF attack
// takes, still arrives without it.
//
// Secure and HttpOnly are unconditional and are half of what the __Host- prefix
// enforces anyway. HttpOnly in particular is what keeps the CSRF derivation
// meaningful: a script that could read the cookie could compute the token.
func setSessionCookie(w http.ResponseWriter, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

// origin reconstructs the origin this request arrived at, for use in messages.
func (s *Server) origin(r *http.Request) string {
	if s.cfg.BaseURL != "" {
		return strings.TrimSuffix(s.cfg.BaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// clientAddr extracts the caller's IP for the session record.
//
// No X-Forwarded-For handling, unlike internal/api. This listener is bound to
// loopback by default and is expected to sit behind a terminator the operator
// controls; reading a client-settable header here would let a caller write any
// address they like into the session audit trail, which is the one place it is
// read back as fact.
func clientAddr(r *http.Request) *netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	a = a.Unmap()
	return &a
}
