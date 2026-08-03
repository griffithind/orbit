-- Tables created by future migrations must reach orbit_app.
--
-- 0002_grants.sql ran:
--
--     GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA orbit TO orbit_app;
--     GRANT USAGE ON ALL SEQUENCES IN SCHEMA orbit TO orbit_app;
--
-- ON ALL TABLES is not a standing rule. Postgres expands it once, at execution
-- time, into one GRANT per table that existed at that instant, and then it is
-- over. Nothing about it applies to a table created afterwards.
--
-- So every table a later migration creates starts with no grant to orbit_app at
-- all, and the failure mode is the bad kind: the migration itself succeeds,
-- because it runs as the admin role, which owns the new table and needs no
-- grant to use it. Nothing looks wrong. The symptom is
-- "permission denied for table ..." the first time the application — connected
-- as orbit_app — touches it, which is in production, one deploy later, rather
-- than at migration time where it would be caught.
--
-- This is latent today only by accident: 0003 dropped a table and 0004 added a
-- column, so no migration has yet created one. The first CREATE TABLE trips it.
--
-- ALTER DEFAULT PRIVILEGES is the standing rule that ON ALL TABLES is not.

--------------------------------------------------------------------------------
-- The role-scoping caveat, stated plainly
--------------------------------------------------------------------------------
--
-- ALTER DEFAULT PRIVILEGES is keyed on (creating role, schema, object type). It
-- is NOT a property of the schema. The rule below reads, in full: "when THIS
-- role creates a table in schema orbit, grant it to orbit_app." A table created
-- in orbit by some other role gets nothing from it.
--
-- internal/db/migrate.go connects as whatever the admin DSN names, and that is
-- a deployment choice, not a schema-controlled one. Concretely: if this file is
-- applied by superuser A, and a later deployment applies migration 0007 with an
-- admin DSN naming superuser B, the table 0007 creates is owned by B, is not
-- covered by A's default privileges, and orbit_app cannot read it. The runtime
-- permission error this migration exists to prevent comes back.
--
-- Postgres offers no fix for that. There is no FOR ANY ROLE, no schema-scoped
-- form, and no way to write a rule that covers a role which does not exist yet
-- or whose name we do not know. A fully role-independent guarantee is NOT
-- achievable in SQL, and this migration does not provide one. What it provides
-- is coverage of every role that has demonstrably created objects in schema
-- orbit so far, plus the role running right now, which is the realistic set.
--
-- Which is why the house convention below is not redundant belt-and-braces
-- pedantry — it is the part that actually survives a role mismatch.

--------------------------------------------------------------------------------
-- HOUSE CONVENTION (a comment is the only enforcement available)
--------------------------------------------------------------------------------
--
--   A migration that creates a table in schema orbit MUST still carry its own
--   explicit grant, immediately after the CREATE TABLE:
--
--       CREATE TABLE orbit.thing (...);
--       GRANT SELECT, INSERT, UPDATE, DELETE ON orbit.thing TO orbit_app;
--       -- and, for a serial/identity column whose sequence the app must touch:
--       -- GRANT USAGE ON SEQUENCE orbit.thing_id_seq TO orbit_app;
--
-- Default privileges cover the common case silently and catch the migration
-- nobody remembered to grant on. The explicit GRANT is what holds when the
-- deployment's admin role is not the one that ran this file. Neither alone is
-- sufficient; write both.

--------------------------------------------------------------------------------

DO $$
DECLARE
    creator text;
    applied int := 0;
BEGIN
    -- 0002 creates orbit_app and always runs first, so this is an assertion
    -- about migration ordering rather than a real branch.
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'orbit_app') THEN
        RAISE EXCEPTION
            'orbit_app does not exist; 0002_grants.sql must be applied before this migration';
    END IF;

    FOR creator IN
        SELECT rolname FROM (
            -- The role applying this migration.
            SELECT current_user::text AS rolname
            UNION
            -- The owner of the schema: the role that ran 0001, and the most
            -- likely creator of anything added later.
            SELECT pg_get_userbyid(nspowner)::text
              FROM pg_namespace WHERE nspname = 'orbit'
            UNION
            -- Every role that has actually created a table or sequence here.
            -- Ordinarily identical to the two above; differs only in a
            -- deployment that has already switched admin roles once, which is
            -- exactly the case worth covering.
            SELECT pg_get_userbyid(c.relowner)::text
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'orbit'
               AND c.relkind IN ('r', 'p', 'S')  -- table, partitioned table, sequence
        ) AS candidates
        WHERE rolname <> 'orbit_app'
          -- ALTER DEFAULT PRIVILEGES FOR ROLE x requires membership in x.
          -- Skipping a role we cannot speak for is better than failing the
          -- migration over a table some unrelated role happens to own.
          AND pg_has_role(current_user, rolname, 'USAGE')
        ORDER BY rolname
    LOOP
        -- Mirrors 0002 exactly. Deliberately not broader: this migration closes
        -- a gap in the existing grant, it does not widen the grant.
        --
        -- Re-running is a no-op. ALTER DEFAULT PRIVILEGES sets an ACL entry
        -- rather than accumulating one, so this file is idempotent and safe to
        -- apply by hand against a database that already has it.
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA orbit '
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO orbit_app', creator);
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA orbit '
            'GRANT USAGE ON SEQUENCES TO orbit_app', creator);

        applied := applied + 1;
        RAISE NOTICE
            'orbit: objects created in schema orbit by % will be granted to orbit_app', creator;
    END LOOP;

    IF applied = 0 THEN
        RAISE EXCEPTION 'no candidate creating role found; default privileges not set';
    END IF;
END
$$;

--------------------------------------------------------------------------------
-- What this does NOT do, and one hazard it creates
--------------------------------------------------------------------------------
--
-- Not retroactive. ALTER DEFAULT PRIVILEGES applies only to objects created
-- after it runs; it does not touch a single existing ACL. That is what keeps
-- the append-only audit log append-only: 0002's
--
--     REVOKE UPDATE, DELETE ON orbit.audit_log FROM orbit_app;
--
-- is untouched by this file, and orbit_app still holds only SELECT and INSERT
-- there. The assertion below turns that reasoning into something the migration
-- checks rather than something a comment claims.
--
-- HAZARD, for whoever adds the next append-only table: the default rule above
-- grants UPDATE and DELETE. A future table that is supposed to be append-only —
-- an outbox, a second audit stream, a signed event log — will silently receive
-- both, because "append-only" is not something the database can infer from a
-- CREATE TABLE. It must be revoked explicitly, in the same migration that
-- creates the table, the way 0002 did:
--
--     REVOKE UPDATE, DELETE ON orbit.new_append_only_table FROM orbit_app;
--
-- Getting this wrong produces no error and no test failure. It produces a log
-- the application can rewrite, which is not a log.

DO $$
BEGIN
    -- Load-bearing. An audit trail the application can rewrite is not an audit
    -- trail, so a migration that granted these back is a migration that must
    -- not commit.
    IF has_table_privilege('orbit_app', 'orbit.audit_log', 'UPDATE')
       OR has_table_privilege('orbit_app', 'orbit.audit_log', 'DELETE') THEN
        RAISE EXCEPTION
            'orbit_app holds UPDATE or DELETE on orbit.audit_log; the audit log is no longer append-only';
    END IF;

    -- The other half: the grant 0002 did intend must still be there, or the
    -- application cannot write the log at all.
    IF NOT has_table_privilege('orbit_app', 'orbit.audit_log', 'SELECT')
       OR NOT has_table_privilege('orbit_app', 'orbit.audit_log', 'INSERT') THEN
        RAISE EXCEPTION 'orbit_app lost SELECT or INSERT on orbit.audit_log';
    END IF;
END
$$;
