-- Browser sessions for the web UI.
--
-- WHAT THIS TABLE IS, AND THE ONE THING IT IS NOT.
--
-- It is a REFERENCE to an API token plus the browser-specific facts a bearer
-- token has no room for: an absolute expiry short enough to survive a stolen
-- laptop, an idle window, and whether the operator asked for a read-only view.
--
-- It is NOT a copy of a credential. There is no scopes column here, and that
-- omission is the entire security argument of this file.
--
-- store.AuthenticateToken filters on revoked_at and expires_at in the SAME
-- query that resolves the token, which is why store.RevokeAPIToken can honestly
-- claim revocation takes effect on the next request with no propagation delay
-- and no cache to invalidate. A session row holding its own copy of the token's
-- scopes would destroy that property silently: revoking the token would leave a
-- live browser session still carrying '*', and nothing in the system would
-- notice, because nothing would ever look at the token again. Storing token_id
-- and re-reading orbit.api_token on every resolve is what keeps one revocation
-- path true for both credentials.
--
-- The consequence is deliberate and is tested: DELETE /v1/tokens/{id} kills
-- every browser session derived from that token, immediately.

CREATE TABLE orbit.ui_session (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The credential this session speaks for. ON DELETE CASCADE is belt and
    -- braces: revocation is the path that matters and it is enforced by the
    -- JOIN in store.ResolveSession, but a token row that is ever genuinely
    -- deleted must not leave sessions pointing at nothing.
    token_id uuid NOT NULL REFERENCES orbit.api_token (id) ON DELETE CASCADE,

    -- SHA-256 of the cookie value. The reasoning in store.NewAPIToken applies
    -- verbatim: the value is 32 bytes from crypto/rand, so a fast hash is the
    -- right choice for the stored form because there is nothing to brute force,
    -- and a database leak yields no usable cookies because SHA-256 is preimage
    -- resistant against a value this large. UNIQUE both because a collision
    -- would be a shared session and because it is the lookup index.
    cookie_hash bytea NOT NULL UNIQUE,

    -- Whether this session is narrowed to the read half of the token's scopes.
    --
    -- A boolean, not a scope list, for the same reason there is no scopes
    -- column: the narrowing is computed from the token's LIVE scopes at every
    -- resolve (store.narrowToReadOnly), so it can only ever intersect them
    -- down. A stored list would be a snapshot, and a snapshot is the thing this
    -- table exists not to be.
    --
    -- No DEFAULT. The caller must decide, because the default belongs at the
    -- login form (where it is on) and a column default would quietly answer for
    -- a future caller that forgot to ask.
    read_only boolean NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),

    -- Absolute expiry: min(12 hours, the token's own expiry), computed in SQL
    -- by store.CreateUISession so that both timestamps come from one now().
    --
    -- The 12 hour ceiling is HERE rather than only in Go because it is the one
    -- bound that must hold no matter which code path, migration, or psql
    -- session inserts the row. It is shorter than the 24 hour default
    -- certificate lifetime a network rotates on, so a cookie can never outlive
    -- the material the fleet itself replaces daily; and it means a laptop
    -- closed at the end of a working day cannot be reopened the next morning
    -- still signed in.
    expires_at timestamptz NOT NULL
        CHECK (expires_at > created_at
               AND expires_at <= created_at + interval '12 hours'),

    -- Refreshed by store.ResolveSession, which also REFUSES a session whose
    -- last_seen_at has fallen outside the idle window. Both happen in the one
    -- statement that resolves the cookie, for the reason the token's revocation
    -- check lives in its resolving query: a check that runs anywhere else is a
    -- check something can be written to skip.
    last_seen_at timestamptz NOT NULL DEFAULT now(),

    -- Sign-out. Nullable and set rather than deleted so the row survives long
    -- enough for the prune sweep to remove it on a schedule rather than the
    -- request path.
    revoked_at timestamptz,

    -- Where the session was minted, and what claimed to mint it. Both are
    -- forensic: "which browser holds this, and from where" is the question an
    -- operator asks about a session they do not recognise.
    --
    -- user_agent is attacker-controlled text. store.CreateUISession truncates
    -- it; the CHECK is the backstop that keeps a caller that forgets from
    -- turning a header into unbounded storage.
    created_ip inet,
    user_agent text CHECK (user_agent IS NULL OR length(user_agent) <= 256)
);

-- The FK needs its own index. Postgres does not create one, so without this
-- every DELETE or UPDATE touching orbit.api_token's primary key sequentially
-- scans this table to check the reference. The table is small and the index is
-- smaller; an unindexed foreign key is a footgun that only shows up under load.
CREATE INDEX ui_session_token_id_idx ON orbit.ui_session (token_id);

--------------------------------------------------------------------------------
-- GRANT
--------------------------------------------------------------------------------
--
-- This migration creates a table, so it carries its own grant. 0002 explains
-- why that is a house rule rather than pedantry: the blanket GRANT ... ON ALL
-- TABLES there was evaluated once and is not a standing rule, and the ALTER
-- DEFAULT PRIVILEGES that backs it up is keyed on the creating role — so a
-- migration applied by a different superuser would leave this table with no
-- grant at all, and the omission surfaces at RUNTIME as a permission error on
-- the login path, not here where it would be caught.
--
-- UPDATE is required: resolving a session refreshes last_seen_at, and signing
-- out sets revoked_at. DELETE is required by the prune sweep. Neither is the
-- append-only case orbit.audit_log is — this is operational state, and the
-- evidence lives in the audit log, which stays unrewritable.
GRANT SELECT, INSERT, UPDATE, DELETE ON orbit.ui_session TO orbit_app;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'ui_session' AND privilege_type = 'INSERT'
    ) THEN
        RAISE EXCEPTION 'orbit_app must hold INSERT on orbit.ui_session';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'ui_session' AND privilege_type = 'UPDATE'
    ) THEN
        RAISE EXCEPTION 'orbit_app must hold UPDATE on orbit.ui_session';
    END IF;
END
$$;

-- Assert the column that must never exist.
--
-- The scope-copy failure is not a bug someone would write on purpose; it is one
-- a future migration adds while making sessions "faster" or "self-contained",
-- and it is invisible in review because a scopes column on a session table
-- looks entirely reasonable. It is not detectable at runtime either: everything
-- keeps working, and the only symptom is a revoked token that still has a live
-- browser attached to it.
--
-- This is a migration-time tripwire, not a constraint — a later migration could
-- of course add the column after this file has run. It is here so that anyone
-- who does has to delete this block first, and read why.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'orbit' AND table_name = 'ui_session'
           AND column_name IN ('scopes', 'token_hash', 'expires_at_token')
    ) THEN
        RAISE EXCEPTION
            'orbit.ui_session must not carry a copy of the token''s scopes or hash: '
            'a session that snapshots them survives revocation of the token it came from';
    END IF;
END
$$;
