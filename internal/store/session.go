package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Browser sessions.
//
// A session is a REFERENCE to an API token, never a copy of one. Everything in
// this file follows from that: the row stores token_id, and ResolveSession
// JOINs orbit.api_token so the token's revocation and expiry are re-applied on
// every single request alongside the session's own. See
// migrations/0010_ui_session.sql for the argument at length, and
// RevokeAPIToken's doc comment for the property being preserved.

// UISessionPrefix marks a session cookie's value, for the reason
// APITokenPrefix marks a token: a leaked string in a log, a HAR file, or a
// support ticket should be identifiable at a glance as an Orbit credential
// rather than as noise.
const UISessionPrefix = "orbses_"

const (
	// SessionMaxLifetime is the absolute ceiling on a session, before the
	// token's own expiry narrows it further.
	//
	// Twelve hours is chosen against two specific things. It is shorter than
	// the 24 hour default certificate lifetime a network rotates on, so a
	// cookie never outlives the material the fleet itself replaces daily; and
	// it does not span a night, so a laptop closed at the end of a working day
	// cannot be reopened the next morning still holding a credential that can
	// reach the control plane. Longer than a working day buys convenience only
	// for the sessions nobody is watching, which are exactly the ones worth
	// ending.
	//
	// The database enforces this ceiling independently (a CHECK on
	// orbit.ui_session), so no code path can mint a longer one.
	SessionMaxLifetime = 12 * time.Hour

	// SessionIdleTimeout ends a session that has stopped being used.
	//
	// The absolute lifetime bounds a stolen cookie; this bounds an ABANDONED
	// browser — the console left open on an unlocked screen, which is the more
	// common of the two by a wide margin and the one an operator cannot revoke
	// because they do not know it happened.
	//
	// Thirty minutes is the point past which an open tab is better modelled as
	// forgotten than as paused. The cost of being wrong is one sign-in, and it
	// falls entirely on humans: /v1 automation authenticates with bearer tokens,
	// which have no idle concept and are not affected by this at all.
	SessionIdleTimeout = 30 * time.Minute
)

// Audit actions for the browser session lifecycle.
//
// Declared here rather than beside their siblings in audit.go, following
// ActionConfigReverted: this file is the only thing that writes them, and the
// alternative — filing a browser sign-in under ActionTokenCreated — would make
// "did anyone open a console session with this credential, and from where"
// unanswerable without reading metadata. A `WHERE action = ...` should reach
// it.
const (
	ActionSessionCreated = "session.created"
	// ActionSessionDenied is a REFUSED sign-in. Its actor is the system, not a
	// token: a denial is precisely the case where the presented credential did
	// not resolve, so there is nobody to attribute it to. The source address is
	// the whole content of the record, and it is what the login rate limit
	// keys on.
	ActionSessionDenied    = "session.denied"
	ActionSessionDestroyed = "session.destroyed"
)

// newSessionCookie generates a cookie value and its stored hash.
//
// 32 random bytes, SHA-256 stored, no pepper — store.NewAPIToken's reasoning
// applies verbatim, and is not repeated here so that the two cannot drift into
// disagreeing accounts of the same decision.
func newSessionCookie() (plaintext string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate session cookie: %w", err)
	}
	plaintext = UISessionPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))
	return plaintext, sum[:], nil
}

// hashSessionCookie is the lookup form of a presented cookie value.
func hashSessionCookie(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

// CreateUISession mints a browser session backed by an existing API token.
//
// The caller keeps the plaintext, which exists only in the Set-Cookie header
// that created it; there is no path back to it from the database.
//
// readOnly should default to TRUE at the login form. The common use of the web
// UI is looking at convergence from a phone, and a cookie jar holding a
// credential that can create certificate authorities is the thing this whole
// layer exists not to build. An operator who actually needs to block a host
// opts out at sign-in and gets a session carrying the token's full scopes.
//
// Returns ErrNotFound if the token is unknown, revoked, or already expired,
// without distinguishing between them: a sign-in form is as much a probing
// oracle as an API is.
//
// The expiry is computed by Postgres, in the same statement that checks the
// token is live, as min(now + SessionMaxLifetime, token.expires_at). Doing it
// in SQL is not a stylistic choice: created_at defaults to now() in the
// database, and a Go-computed expiry would be compared against it by the
// table's 12 hour CHECK, so the smallest clock skew between the application
// and Postgres would start refusing valid sign-ins.
func (t *Tx) CreateUISession(ctx context.Context, tokenID uuid.UUID, readOnly bool, ip *netip.Addr, userAgent string) (plaintext string, expiresAt time.Time, err error) {
	plaintext, hash, err := newSessionCookie()
	if err != nil {
		return "", time.Time{}, err
	}

	// Truncated rather than refused. A header this long is a client being
	// strange, not a request worth failing; the column's CHECK is the backstop.
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}

	var (
		sessionID uuid.UUID
		ipArg     any
		uaArg     any
	)
	if ip != nil && ip.IsValid() {
		ipArg = *ip
	}
	if userAgent != "" {
		uaArg = userAgent
	}

	err = t.tx.QueryRow(ctx, `
		INSERT INTO orbit.ui_session
			(token_id, cookie_hash, read_only, expires_at, created_ip, user_agent)
		SELECT tok.id, $2, $3,
		       least(now() + make_interval(secs => $4),
		             coalesce(tok.expires_at, 'infinity'::timestamptz)),
		       $5, $6
		  FROM orbit.api_token tok
		 WHERE tok.id = $1
		   AND tok.revoked_at IS NULL
		   AND (tok.expires_at IS NULL OR tok.expires_at > now())
		RETURNING id, expires_at`,
		tokenID, hash, readOnly, SessionMaxLifetime.Seconds(), ipArg, uaArg,
	).Scan(&sessionID, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The INSERT ... SELECT matched no token, which is the token being
			// unknown, revoked, or expired. Not a row that failed to insert.
			return "", time.Time{}, ErrNotFound
		}
		return "", time.Time{}, mapErr(err, "create ui session")
	}

	// The audit entry is written here rather than left to the caller, for the
	// reason Identity.Audit exists: the actor is the part that is always the
	// same and always easy to get subtly wrong. A sign-in that is not recorded
	// is worse than a failed one.
	var name string
	if err := t.tx.QueryRow(ctx,
		`SELECT name FROM orbit.api_token WHERE id = $1`, tokenID).Scan(&name); err != nil {
		return "", time.Time{}, mapErr(err, "read token name")
	}
	meta, err := json.Marshal(map[string]any{
		"read_only":  readOnly,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
		"user_agent": userAgent,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encode session audit metadata: %w", err)
	}
	if err := t.AppendAudit(ctx, AuditEntry{
		ActorType: ActorToken, ActorID: tokenID.String(), ActorDisplay: name,
		Action:     ActionSessionCreated,
		TargetType: "session", TargetID: sessionID.String(),
		Meta: meta, SourceIP: ip,
	}); err != nil {
		return "", time.Time{}, err
	}
	return plaintext, expiresAt, nil
}

// ResolveSession authenticates a browser session cookie.
//
// It returns the same *Identity AuthenticateToken returns, populated from the
// token the session references, so no handler, scope check, or audit call site
// below this point learns that sessions exist.
//
// Four conditions are checked in the ONE statement that resolves the cookie —
// the session's revocation, the session's absolute expiry, the session's idle
// window, and the TOKEN's revocation and expiry. The last of those is the point
// of this design. Because the token is re-read here on every request rather
// than snapshotted at sign-in, revoking a token ends every browser session
// derived from it on the next request, with no propagation delay and no cache
// to invalidate — the property RevokeAPIToken's doc claims, extended to a
// credential type it predates.
//
// The same statement refreshes last_seen_at. The idle check and its refresh
// belong together for the same reason the revocation check belongs in the
// resolving query: a check that runs somewhere else is a check that something
// can be written to skip.
//
// Returns ErrNotFound for an unknown, revoked, expired, or idle-timed-out
// session, and for a live session whose token has been revoked, without
// distinguishing between them.
func (s *Store) ResolveSession(ctx context.Context, cookieValue string) (*Identity, error) {
	var (
		id       Identity
		readOnly bool
	)
	err := s.pool.QueryRow(ctx, `
		UPDATE orbit.ui_session s
		   SET last_seen_at = now()
		  FROM orbit.api_token tok
		 WHERE s.cookie_hash = $1
		   AND tok.id = s.token_id
		   AND s.revoked_at IS NULL
		   AND s.expires_at > now()
		   AND s.last_seen_at > now() - make_interval(secs => $2)
		   AND tok.revoked_at IS NULL
		   AND (tok.expires_at IS NULL OR tok.expires_at > now())
		RETURNING tok.id, tok.name, tok.scopes, s.expires_at, s.read_only`,
		hashSessionCookie(cookieValue), SessionIdleTimeout.Seconds(),
	).Scan(&id.TokenID, &id.Display, &id.Scopes, &id.ExpiresAt, &readOnly)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapErr(err, "resolve session")
	}

	// The narrowing happens HERE, on scopes just read from the live token row,
	// so it can only ever intersect them down. Doing it at sign-in and storing
	// the result would be the snapshot this whole file refuses to keep.
	if readOnly {
		id.Scopes = narrowToReadOnly(id.Scopes)
	}

	// ExpiresAt is the SESSION's expiry, not the token's. It is what the caller
	// is actually holding — it is by construction the earlier of the two — and
	// it is the number a console needs to say how long is left before signing
	// out. Identity does not describe the credential's shape, only its life.
	id.Kind = ActorToken
	id.Subject = id.TokenID.String()
	return &id, nil
}

// RevokeUISession signs a browser session out.
//
// Returns ErrNotFound for an unknown cookie or one already revoked, matching
// RevokeAPIToken: a caller is entitled to know whether it was the one that
// ended the session. A sign-out handler should clear the cookie regardless.
//
// Deliberately does NOT touch the token. Signing out of a browser must not
// revoke the credential an operator's shell is also using, which is the whole
// reason a session is a separate row rather than a second token.
func (t *Tx) RevokeUISession(ctx context.Context, cookieValue string) error {
	var (
		sessionID uuid.UUID
		tokenID   uuid.UUID
		name      string
	)
	err := t.tx.QueryRow(ctx, `
		UPDATE orbit.ui_session s
		   SET revoked_at = now()
		  FROM orbit.api_token tok
		 WHERE s.cookie_hash = $1
		   AND s.revoked_at IS NULL
		   AND tok.id = s.token_id
		RETURNING s.id, tok.id, tok.name`,
		hashSessionCookie(cookieValue),
	).Scan(&sessionID, &tokenID, &name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("revoke ui session: %w", ErrNotFound)
		}
		return mapErr(err, "revoke ui session")
	}

	return t.AppendAudit(ctx, AuditEntry{
		ActorType: ActorToken, ActorID: tokenID.String(), ActorDisplay: name,
		Action:     ActionSessionDestroyed,
		TargetType: "session", TargetID: sessionID.String(),
	})
}

// AuditSessionDenied records a refused sign-in.
//
// Separate from the create path because a denial has no session and no
// identity — the credential presented did not resolve, so there is nothing to
// attribute it to and no row to point at. What is left is the source address,
// which is exactly what an operator needs when the audit log shows a run of
// these.
//
// A method on Tx so the entry commits with whatever else the login handler
// does. Not folded into CreateUISession: most denials never reach it, because
// AuthenticateToken has already refused the credential.
func (t *Tx) AuditSessionDenied(ctx context.Context, reason string, ip *netip.Addr) error {
	meta, err := json.Marshal(map[string]any{"reason": reason})
	if err != nil {
		return fmt.Errorf("encode session denial metadata: %w", err)
	}
	return t.AppendAudit(ctx, AuditEntry{
		ActorType: ActorSystem,
		Action:    ActionSessionDenied,
		// No target: naming one would mean naming the credential that was
		// refused, and the refusal path is precisely where we must not confirm
		// that a given credential exists.
		TargetType: "session",
		Meta:       meta, SourceIP: ip,
	})
}

// PruneUISessions removes sessions that expired before the given time.
//
// expires_at alone is a sufficient predicate for every dead session, which is
// worth stating because it looks incomplete. Revoked and idle-timed-out
// sessions are not matched by name here, but both are already unusable —
// ResolveSession refuses them — and every row's expires_at is at most
// created_at + SessionMaxLifetime, so every row becomes prunable within twelve
// hours no matter how it died. A second clause would buy a slightly earlier
// delete of rows that cannot be used either way.
//
// Belongs in the internal/sched sweep, beside PruneExpiredCredentialsAll: it is
// not per network, and nothing about correctness depends on it running.
func (t *Tx) PruneUISessions(ctx context.Context, before time.Time) (int64, error) {
	tag, err := t.tx.Exec(ctx,
		`DELETE FROM orbit.ui_session WHERE expires_at < $1`, before)
	if err != nil {
		return 0, mapErr(err, "prune ui sessions")
	}
	return tag.RowsAffected(), nil
}

// readOnlyScopes is the read half of the API's scope table.
//
// Duplicated from api.knownScopes because store cannot import api — api imports
// store — and the expansion of "*" genuinely needs the list: an intersection
// with a wildcard has to be written out to be an intersection at all.
// api.ReadOnlyScopes() derives the same set from knownScopes, and
// session_test.go asserts the two agree, so adding a scope in one place and not
// the other is a test failure rather than a discovery.
//
// If the assertion were ever to fail unnoticed the failure is closed, not open:
// a read scope missing from this list is one a read-only session on a "*" token
// does not get.
var readOnlyScopes = []string{
	"audit:read",
	"cas:read",
	"hosts:read",
	"networks:read",
	"policy:read",
	"roles:read",
	"tokens:read",
}

// ReadOnlyScopes returns the scopes a read-only session may hold when its token
// carries "*". Exported for the test that keeps it in step with the API's scope
// table, and for a console that wants to show what a read-only session can do.
func ReadOnlyScopes() []string { return slices.Clone(readOnlyScopes) }

// narrowToReadOnly intersects a token's scopes down to the read-only subset.
//
// It never widens, and that is the property to check when reading it: every
// returned scope is either one the token already held, or — in the wildcard
// case — one "*" already implied. A token holding hosts:read and hosts:write
// yields hosts:read; a token holding only hosts:write yields nothing, and a
// read-only session on it can do nothing, which is the correct answer rather
// than a bug.
func narrowToReadOnly(scopes []string) []string {
	if slices.Contains(scopes, "*") {
		// "*" passes HasScope for everything, so it cannot be carried into a
		// narrowed session under any circumstances. Expanding it is the only
		// way to intersect it with anything.
		return slices.Clone(readOnlyScopes)
	}

	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		// The suffix rule, rather than membership of readOnlyScopes: a scope
		// added to the API later and not yet listed above must not be granted
		// to a read-only session by accident, and a WRITE scope must never be,
		// however it is spelled.
		if strings.HasSuffix(s, ":read") {
			out = append(out, s)
		}
	}
	return out
}
