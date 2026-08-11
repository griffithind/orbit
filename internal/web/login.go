package web

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/store"
)

// Sign-in.
//
// The credential is an ordinary Orbit API token — the same string `orbit token
// create` prints and the same one /v1 takes. There is no second user database,
// no password, and nothing new to rotate, which matters because a break-glass
// path with its own credential is a credential nobody has tested since the day
// it was created.
//
// What the session adds is the ability to REVOKE the browser's access without
// revoking the token: closing a laptop lid should not mean rotating the
// credential that automation also uses.

// loginLimit bounds sign-in attempts per source address.
//
// It reuses internal/api's limiter rather than growing a second one. The
// dependency runs one way — api does not import web — and the alternative is two
// implementations of the same eviction-and-global-ceiling logic, one of which
// would be the untested one.
//
// The budget is smaller than enrollment's. An operator signing in makes one
// request and occasionally retries a typo; nothing legitimate here arrives at a
// rate. What it stops is not guessing — a token is 256 bits of randomness and
// there is nothing to guess — but a loop of failed sign-ins each costing a hash
// and a query, and it is what store.AuditSessionDenied's run of entries is meant
// to key on.
func newLoginLimiter() *api.Limiter {
	return api.NewLimiter(api.LimiterConfig{
		PerMinute: 10, Burst: 10,
		GlobalPerMinute: 60, GlobalBurst: 30,
	})
}

// loginKey buckets a source address for the limiter.
//
// IPv6 by /64, because a single client routinely holds a whole /64 and can
// source from any address in it — a per-address limit there would look like it
// was working while being trivially bypassed.
func loginKey(ip *netip.Addr) string {
	if ip == nil {
		return "unknown"
	}
	if ip.Is6() && !ip.Is4In6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip.String()
}

type loginView struct {
	Next string
	Note string
	// Problem is the failure from a previous attempt, rendered in the form
	// rather than as a banner so it sits next to the field that caused it.
	Problem string
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) error {
	// Already signed in and arriving at the login form is almost always a
	// bookmark. Send them where they were going rather than asking again.
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		if _, err := s.sessions.Resolve(r.Context(), c.Value); err == nil {
			http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
			return nil
		}
	}

	p := s.newPage(r, "Sign in")
	p.Data = loginView{
		Next: safeNext(r.URL.Query().Get("next")),
		// Signed, like every other banner. This is the page where an admin
		// token is typed and where the read-only default can be argued out of,
		// so it is the worst one to let a stranger write.
		Note: s.verifiedNotice(r),
	}
	return s.render(w, r, "login.html", http.StatusOK, p)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	token := strings.TrimSpace(r.PostFormValue("token"))
	next := safeNext(r.PostFormValue("next"))

	// READ-ONLY IS THE DEFAULT, and the field is named for the opt-out rather
	// than for the safe state deliberately. An unchecked checkbox submits
	// nothing, so if this were named read_only, any request that simply omitted
	// the field — a scripted sign-in, a form rendered by an older build, a proxy
	// that dropped it — would produce a session with the token's full scopes.
	// Named this way, absence means the narrow session, and the dangerous state
	// is the one that has to be asked for explicitly.
	//
	// store.ResolveSession does the enforcing: it intersects the live token's
	// scopes down to the :read subset on every request, so a read-only session
	// fails the same HasScope check every other credential does. Nothing in this
	// package has to remember.
	readOnly := r.PostFormValue("full_access") == ""

	fail := func(msg string) error {
		p := s.newPage(r, "Sign in")
		p.Data = loginView{Next: next, Problem: msg}
		// 401, not 200. The status code is the only part of this a monitoring
		// system can see, and a login page that answers 200 to a failed attempt
		// is one that cannot be alerted on.
		return s.render(w, r, "login.html", http.StatusUnauthorized, p)
	}

	if token == "" {
		return fail("Enter an API token.")
	}

	ip := clientAddr(r)
	if !s.loginLimit.Allow(loginKey(ip)) {
		s.log.Warn("ui sign-in rate limited", "from", loginKey(ip))
		w.Header().Set("Retry-After", strconv.Itoa(30))
		p := s.newPage(r, "Sign in")
		p.Data = loginView{Next: next, Problem: "Too many sign-in attempts. Wait a moment and try again."}
		return s.render(w, r, "login.html", http.StatusTooManyRequests, p)
	}

	// The same authentication /v1 does, against the same table, so a token that
	// works there works here and a revoked one works in neither. Note what is NOT
	// happening: there is no separate password check, no cached identity, and no
	// second code path that could drift from the one the API uses.
	id, err := s.store.AuthenticateToken(r.Context(), hashToken(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Unknown, expired, and revoked are one message, for the reason the
			// API gives: a distinguishable failure is an oracle.
			//
			// Recorded, because a run of these from one address is the signal an
			// operator is meant to find in the audit log, and the source address
			// is the whole content of the record — the credential presented did
			// not resolve, so there is nobody to attribute it to.
			s.auditDeniedSignIn(r.Context(), "invalid token", ip)
			s.log.Warn("ui sign-in refused", "remote", r.RemoteAddr)
			return fail("That token is not valid. It may have been revoked or have expired.")
		}
		return err
	}

	value, expires, err := s.sessions.Create(r.Context(), id.TokenID, readOnly, ip, r.UserAgent())
	if err != nil {
		return err
	}
	setSessionCookie(w, value, expires)

	s.log.Info("ui sign-in", "actor", id.Display, "token", id.TokenID,
		"readOnly", readOnly, "expires", expires)

	// 303, so a refresh of the destination does not re-POST the token.
	http.Redirect(w, r, next, http.StatusSeeOther)
	return nil
}

// auditDeniedSignIn records a refused sign-in, best effort.
//
// Best effort because the alternative is worse: a login page that returns 500
// when the audit write fails tells an operator with a perfectly good token that
// the system is broken, at the moment they are trying to get in and fix
// something else.
func (s *Server) auditDeniedSignIn(ctx context.Context, reason string, ip *netip.Addr) {
	err := s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.AuditSessionDenied(ctx, reason, ip)
	})
	if err != nil {
		s.log.Error("could not record a denied sign-in", "error", err)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) error {
	cookie := cookieFrom(r.Context())
	if cookie != "" {
		if err := s.sessions.Revoke(r.Context(), cookie); err != nil && !errors.Is(err, store.ErrNotFound) {
			// Logged, not surfaced. The cookie is cleared below either way, so
			// the browser is signed out; failing the request would leave an
			// operator staring at an error while still appearing signed in.
			s.log.Error("ui session revoke failed", "error", err)
		}
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/ui/login?"+s.signNotice("You are signed out.").Encode(), http.StatusSeeOther)
	return nil
}

// safeNext sanitises a post-login redirect target.
//
// An OPEN REDIRECT here would be worth having: this is the one page in the
// product where an operator types a credential, so a link that lands them on a
// convincing copy of it on another host is the highest-value phish in the
// system. Only a path on this origin is accepted — not a scheme, not a host, and
// not "//evil.example", which a browser reads as a protocol-relative URL to
// another origin however much it looks like a path.
func safeNext(next string) string {
	const fallback = "/ui/"
	if next == "" {
		return fallback
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return fallback
	}
	// Backslashes, because some browsers normalise them to forward slashes and
	// "/\evil.example" then means the same thing as "//evil.example".
	if strings.Contains(next, `\`) {
		return fallback
	}
	if !strings.HasPrefix(next, "/ui/") && next != "/ui" {
		// Nothing outside the UI is a legitimate destination, and this listener
		// serves nothing else.
		return fallback
	}
	return next
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
