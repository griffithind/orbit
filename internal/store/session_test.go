package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/store"
)

// Browser sessions.
//
// The property under test throughout is that a session is a REFERENCE to a
// token and not a copy of one. Everything else here — the expiry, the idle
// window, the narrowing — is secondary to that, and the first test is the one
// that would make all the others pointless if it failed.

// newToken creates an API token and returns its id and plaintext.
func newToken(t *testing.T, s *store.Store, scopes []string, expiresAt *time.Time) (uuid.UUID, string) {
	t.Helper()

	plaintext, hash, err := store.NewAPIToken()
	if err != nil {
		t.Fatalf("NewAPIToken: %v", err)
	}
	var id uuid.UUID
	err = s.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		id, err = tx.CreateAPIToken(ctx, "session-test-"+uuid.NewString()[:8], hash, scopes, expiresAt)
		return err
	})
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	return id, plaintext
}

// newSession signs in and returns the cookie value.
func newSession(t *testing.T, s *store.Store, tokenID uuid.UUID, readOnly bool) (string, time.Time) {
	t.Helper()

	from := netip.MustParseAddr("198.51.100.9")
	var (
		cookie  string
		expires time.Time
	)
	err := s.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		cookie, expires, err = tx.CreateUISession(ctx, tokenID, readOnly, &from, "Mozilla/5.0 (test)")
		return err
	})
	if err != nil {
		t.Fatalf("CreateUISession: %v", err)
	}
	return cookie, expires
}

// adminConn opens a connection as the migration role, for the handful of
// assertions that need to reach past the store: backdating a row to age a
// session, and reading the stored cookie_hash to prove the plaintext is not
// there. Nothing in the application does either.
func adminConn(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), adminDSN())
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// TestRevokingATokenKillsItsSessions is THE test.
//
// If a session held its own copy of the token's scopes this would still pass
// every functional test in this file and fail only here — and in production it
// would fail silently, as a revoked credential with a live browser attached to
// it and nothing anywhere reporting a problem.
func TestRevokingATokenKillsItsSessions(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	tokenID, _ := newToken(t, s, []string{"hosts:read", "hosts:write"}, nil)
	cookie, _ := newSession(t, s, tokenID, false)

	if _, err := s.ResolveSession(ctx, cookie); err != nil {
		t.Fatalf("session should resolve before revocation: %v", err)
	}

	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RevokeAPIToken(ctx, tokenID)
	}); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}

	// Immediately. No sweep, no cache invalidation, no next-poll delay: the
	// very next resolve re-reads the token row and finds revoked_at set.
	if _, err := s.ResolveSession(ctx, cookie); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session survived revocation of the token it came from: err = %v", err)
	}
}

// TestSignInRefusesADeadToken closes the other half: a session cannot be minted
// from a credential that is already gone. Without this, revocation would be a
// race rather than an end — revoke, then sign in with the string you still
// have.
func TestSignInRefusesADeadToken(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	revoked, _ := newToken(t, s, []string{"*"}, nil)
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RevokeAPIToken(ctx, revoked)
	}); err != nil {
		t.Fatal(err)
	}

	past := time.Now().Add(-time.Hour)
	expired, _ := newToken(t, s, []string{"*"}, &past)

	for name, id := range map[string]uuid.UUID{
		"revoked": revoked,
		"expired": expired,
		"unknown": uuid.New(),
	} {
		err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
			_, _, err := tx.CreateUISession(ctx, id, true, nil, "")
			return err
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CreateUISession on a %s token = %v, want ErrNotFound", name, err)
		}
	}
}

// TestReadOnlySessionCannotWiden. The narrowing must be an intersection in
// every case, including the one that matters most: a "*" token, which is what a
// bootstrap or break-glass credential holds and exactly the thing nobody should
// be carrying around in a cookie jar.
func TestReadOnlySessionCannotWiden(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		token []string
		want  []string
	}{
		{
			name:  "wildcard expands to the read set and nothing more",
			token: []string{"*"},
			want:  store.ReadOnlyScopes(),
		},
		{
			name:  "a mixed token keeps only its read scopes",
			token: []string{"hosts:read", "hosts:write", "hosts:block", "cas:write"},
			want:  []string{"hosts:read"},
		},
		{
			name:  "a write-only token yields a session that can do nothing",
			token: []string{"hosts:write", "cas:write"},
			want:  []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenID, _ := newToken(t, s, tc.token, nil)
			cookie, _ := newSession(t, s, tokenID, true)

			id, err := s.ResolveSession(ctx, cookie)
			if err != nil {
				t.Fatalf("ResolveSession: %v", err)
			}

			got := slices.Clone(id.Scopes)
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("read-only session scopes = %v, want %v", got, want)
			}

			// The property stated directly, rather than inferred from the list.
			for _, sc := range id.Scopes {
				if sc == "*" {
					t.Fatal("a read-only session carries \"*\"; the narrowing did not happen")
				}
				if !strings.HasSuffix(sc, ":read") {
					t.Errorf("read-only session holds a non-read scope %q", sc)
				}
			}
			if id.HasScope("hosts:write") || id.HasScope("cas:write") {
				t.Error("a read-only session passes a write scope check")
			}
		})
	}
}

// TestFullSessionKeepsTheTokensScopes. Opting out of read-only must produce the
// token's scopes exactly — the same identity a bearer token produces — or the
// escape hatch for "I need to block a host" does not exist.
func TestFullSessionKeepsTheTokensScopes(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	scopes := []string{"hosts:read", "hosts:block"}
	tokenID, plaintext := newToken(t, s, scopes, nil)
	cookie, _ := newSession(t, s, tokenID, false)

	fromCookie, err := s.ResolveSession(ctx, cookie)
	if err != nil {
		t.Fatalf("ResolveSession: %v", err)
	}
	sum := sha256.Sum256([]byte(plaintext))
	fromBearer, err := s.AuthenticateToken(ctx, sum[:])
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}

	// Nothing downstream may be able to tell these apart. ExpiresAt is the one
	// field that legitimately differs: it reports the life of the credential
	// actually in the caller's hand.
	if fromCookie.Kind != fromBearer.Kind || fromCookie.Subject != fromBearer.Subject ||
		fromCookie.Display != fromBearer.Display || fromCookie.TokenID != fromBearer.TokenID {
		t.Errorf("session identity differs from token identity:\n cookie %+v\n bearer %+v",
			fromCookie, fromBearer)
	}
	if !slices.Equal(fromCookie.Scopes, scopes) {
		t.Errorf("full session scopes = %v, want %v", fromCookie.Scopes, scopes)
	}
}

// TestExpiredSessionIsRefused, in both of its flavours: the absolute expiry and
// the idle window.
func TestExpiredSessionIsRefused(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	conn := adminConn(t)

	for _, tc := range []struct {
		name string
		age  string
	}{
		{
			name: "past its absolute expiry",
			// The CHECK requires expires_at <= created_at + 12h, so the row has
			// to be backdated as a whole rather than just have its expiry
			// moved. That the constraint makes this awkward is the point.
			age: `created_at = now() - interval '13 hours',
			      expires_at = now() - interval '1 hour',
			      last_seen_at = now()`,
		},
		{
			name: "idle past the timeout",
			age:  `last_seen_at = now() - interval '31 minutes'`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenID, _ := newToken(t, s, []string{"hosts:read"}, nil)
			cookie, _ := newSession(t, s, tokenID, true)

			sum := sha256.Sum256([]byte(cookie))
			if _, err := conn.Exec(ctx,
				`UPDATE orbit.ui_session SET `+tc.age+` WHERE cookie_hash = $1`, sum[:]); err != nil {
				t.Fatalf("age the session: %v", err)
			}

			if _, err := s.ResolveSession(ctx, cookie); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("ResolveSession on a session %s = %v, want ErrNotFound", tc.name, err)
			}
		})
	}
}

// TestResolveRefreshesTheIdleWindow. The idle timeout must be measured from the
// last request, not from sign-in, or it is a second and much shorter absolute
// expiry wearing the wrong name.
func TestResolveRefreshesTheIdleWindow(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	conn := adminConn(t)

	tokenID, _ := newToken(t, s, []string{"hosts:read"}, nil)
	cookie, _ := newSession(t, s, tokenID, true)
	sum := sha256.Sum256([]byte(cookie))

	// Inside the window, but old enough that a failure to refresh is visible.
	if _, err := conn.Exec(ctx,
		`UPDATE orbit.ui_session SET last_seen_at = now() - interval '29 minutes'
		  WHERE cookie_hash = $1`, sum[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveSession(ctx, cookie); err != nil {
		t.Fatalf("a session 29 minutes idle should resolve: %v", err)
	}

	var idle time.Duration
	var seconds float64
	if err := conn.QueryRow(ctx,
		`SELECT extract(epoch FROM now() - last_seen_at) FROM orbit.ui_session
		  WHERE cookie_hash = $1`, sum[:]).Scan(&seconds); err != nil {
		t.Fatal(err)
	}
	idle = time.Duration(seconds * float64(time.Second))
	if idle > time.Minute {
		t.Errorf("last_seen_at was not refreshed by the resolve: still %s old", idle)
	}
}

// TestSessionNeverOutlivesItsToken. The absolute expiry is
// min(12h, token.expires_at), so a short-lived credential — the shape a
// break-glass token takes — cannot be laundered into a twelve hour cookie.
func TestSessionNeverOutlivesItsToken(t *testing.T) {
	s := setup(t)

	shortly := time.Now().Add(45 * time.Minute)
	tokenID, _ := newToken(t, s, []string{"hosts:read"}, &shortly)
	_, expires := newSession(t, s, tokenID, true)

	if expires.After(shortly.Add(time.Minute)) {
		t.Errorf("session expires at %s, after its token's %s", expires, shortly)
	}

	// And the ceiling still applies to a token that never expires.
	forever, _ := newToken(t, s, []string{"hosts:read"}, nil)
	_, capped := newSession(t, s, forever, true)
	if capped.After(time.Now().Add(store.SessionMaxLifetime + time.Minute)) {
		t.Errorf("session expires at %s, beyond the %s ceiling", capped, store.SessionMaxLifetime)
	}
}

// TestTwelveHourCeilingIsEnforcedByTheDatabase. The Go constant is policy; this
// is the invariant. A future caller computing its own expiry cannot get past
// it, which is the reason it is a CHECK rather than a comment.
func TestTwelveHourCeilingIsEnforcedByTheDatabase(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	conn := adminConn(t)

	tokenID, _ := newToken(t, s, []string{"hosts:read"}, nil)

	_, err := conn.Exec(ctx, `
		INSERT INTO orbit.ui_session (token_id, cookie_hash, read_only, expires_at)
		VALUES ($1, $2, true, now() + interval '30 days')`,
		tokenID, []byte("not-a-real-hash-but-unique-"+uuid.NewString()))
	if err == nil {
		t.Fatal("the database accepted a 30 day session")
	}
	if !strings.Contains(err.Error(), "ui_session") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// TestCookieValueIsNotStoredInPlaintext. A database leak must not yield usable
// cookies, which is the same claim NewAPIToken makes and the reason the column
// is a hash.
func TestCookieValueIsNotStoredInPlaintext(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	conn := adminConn(t)

	tokenID, _ := newToken(t, s, []string{"hosts:read"}, nil)
	cookie, _ := newSession(t, s, tokenID, true)

	// Every text-ish column of the row, not just the one we expect. The failure
	// this guards against is a well-meant "store it for debugging" column.
	var found int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM orbit.ui_session
		 WHERE encode(cookie_hash, 'escape') LIKE '%' || $1 || '%'
		    OR coalesce(user_agent, '') LIKE '%' || $1 || '%'`, cookie).Scan(&found); err != nil {
		t.Fatal(err)
	}
	if found != 0 {
		t.Error("the cookie value appears in orbit.ui_session in recoverable form")
	}

	sum := sha256.Sum256([]byte(cookie))
	var stored []byte
	if err := conn.QueryRow(ctx,
		`SELECT cookie_hash FROM orbit.ui_session WHERE cookie_hash = $1`, sum[:]).Scan(&stored); err != nil {
		t.Fatalf("the row is not addressable by the hash of its cookie: %v", err)
	}

	// And the audit trail must not carry it either: the entry records the
	// session, and a credential in an append-only log is a credential nobody
	// can delete.
	var inAudit int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM orbit.audit_log WHERE meta::text LIKE '%' || $1 || '%'`,
		cookie).Scan(&inAudit); err != nil {
		t.Fatal(err)
	}
	if inAudit != 0 {
		t.Error("the cookie value was written to the audit log")
	}
}

// TestRevokeUISession is sign-out: the session ends, and the token does not.
func TestRevokeUISession(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	tokenID, plaintext := newToken(t, s, []string{"hosts:read"}, nil)
	cookie, _ := newSession(t, s, tokenID, true)

	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RevokeUISession(ctx, cookie)
	}); err != nil {
		t.Fatalf("RevokeUISession: %v", err)
	}
	if _, err := s.ResolveSession(ctx, cookie); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a signed-out session still resolves: %v", err)
	}

	// The operator's shell keeps working. If signing out of the console
	// revoked the token, a session would be a worse thing to hand someone than
	// a second token.
	sum := sha256.Sum256([]byte(plaintext))
	if _, err := s.AuthenticateToken(ctx, sum[:]); err != nil {
		t.Errorf("signing out of the browser revoked the underlying token: %v", err)
	}

	// A second sign-out reports ErrNotFound rather than succeeding silently,
	// matching RevokeAPIToken.
	err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RevokeUISession(ctx, cookie)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("double sign-out = %v, want ErrNotFound", err)
	}
}

// TestUnknownCookieIsRefused. Includes a value shaped like a real one, so the
// test is not passing on a length check somewhere.
func TestUnknownCookieIsRefused(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	for _, v := range []string{"", "garbage", store.UISessionPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := s.ResolveSession(ctx, v); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ResolveSession(%q) = %v, want ErrNotFound", v, err)
		}
	}
}

// TestPruneUISessions. Pruning is hygiene, not enforcement — an expired session
// is already refused — so the only thing to prove is that rows do not
// accumulate forever and that a live one survives the sweep.
func TestPruneUISessions(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	conn := adminConn(t)

	tokenID, _ := newToken(t, s, []string{"hosts:read"}, nil)
	dead, _ := newSession(t, s, tokenID, true)
	live, _ := newSession(t, s, tokenID, true)

	deadHash := sha256.Sum256([]byte(dead))
	if _, err := conn.Exec(ctx, `
		UPDATE orbit.ui_session
		   SET created_at = now() - interval '13 hours', expires_at = now() - interval '1 hour'
		 WHERE cookie_hash = $1`, deadHash[:]); err != nil {
		t.Fatal(err)
	}

	var pruned int64
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		pruned, err = tx.PruneUISessions(ctx, time.Now())
		return err
	}); err != nil {
		t.Fatalf("PruneUISessions: %v", err)
	}
	if pruned < 1 {
		t.Errorf("pruned %d sessions, want at least the expired one", pruned)
	}

	var n int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM orbit.ui_session WHERE cookie_hash = $1`, deadHash[:]).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("the expired session survived the prune")
	}
	if _, err := s.ResolveSession(ctx, live); err != nil {
		t.Errorf("the prune took a live session with it: %v", err)
	}
}

// TestSessionLifecycleIsAudited. A sign-in that leaves no trace is the one an
// incident cannot reconstruct, and the actor has to be the token — not
// "system" — or the entry answers nothing.
func TestSessionLifecycleIsAudited(t *testing.T) {
	s := setup(t)
	ctx := context.Background()

	tokenID, _ := newToken(t, s, []string{"hosts:read"}, nil)
	cookie, _ := newSession(t, s, tokenID, true)
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RevokeUISession(ctx, cookie)
	}); err != nil {
		t.Fatal(err)
	}

	from := netip.MustParseAddr("203.0.113.4")
	if err := s.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.AuditSessionDenied(ctx, "unknown token", &from)
	}); err != nil {
		t.Fatalf("AuditSessionDenied: %v", err)
	}

	for _, tc := range []struct {
		action    string
		actorType string
		actorID   string
	}{
		{store.ActionSessionCreated, store.ActorToken, tokenID.String()},
		{store.ActionSessionDestroyed, store.ActorToken, tokenID.String()},
		{store.ActionSessionDenied, store.ActorSystem, ""},
	} {
		var recs []store.AuditRecord
		if err := s.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
			var err error
			recs, err = tx.ListAudit(ctx, store.AuditFilter{Action: tc.action, Limit: 50})
			return err
		}); err != nil {
			t.Fatal(err)
		}

		found := false
		for _, r := range recs {
			if r.ActorType == tc.actorType && r.ActorID == tc.actorID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no %s entry with actor_type=%q actor_id=%q", tc.action, tc.actorType, tc.actorID)
		}
	}
}

// TestReadOnlyScopesMatchTheAPIScopeTable keeps the one duplicated list honest.
//
// store cannot import api, and expanding "*" is the single case an intersection
// cannot be written without enumerating the set — so the list exists twice. This
// is what makes that safe: adding a scope to api.knownScopes and forgetting
// store.readOnlyScopes fails here rather than becoming a scope read-only
// sessions quietly never get.
func TestReadOnlyScopesMatchTheAPIScopeTable(t *testing.T) {
	fromAPI := api.ReadOnlyScopes()
	fromStore := store.ReadOnlyScopes()
	slices.Sort(fromAPI)
	slices.Sort(fromStore)

	if !slices.Equal(fromAPI, fromStore) {
		t.Errorf("the read-scope lists have drifted.\n api.ReadOnlyScopes()   = %v\n"+
			" store.ReadOnlyScopes() = %v\n"+
			"Add the missing scope to store.readOnlyScopes in internal/store/session.go.",
			fromAPI, fromStore)
	}
}
