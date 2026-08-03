-- Least privilege for the application role.
--
-- Two properties, neither of which is about isolation:
--
--   * The application issues no DDL, so it holds no CREATE.
--   * The audit log is append-only. Not "we don't update it" — the application
--     role has no grant to. An audit trail the application can rewrite is not
--     an audit trail.
--
-- The application connects as orbit_app rather than as the migration role, so a
-- bug cannot alter the schema and a compromise cannot quietly drop the audit
-- table.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'orbit_app') THEN
        CREATE ROLE orbit_app NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA orbit TO orbit_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA orbit TO orbit_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA orbit TO orbit_app;

-- GRANT ... ON ALL TABLES above is evaluated once, right now. It is not a
-- standing rule, so a table created by any later migration would get no grant
-- at all — and that failure surfaces at RUNTIME as a permission error, not at
-- migration time where it would be caught.
--
-- ALTER DEFAULT PRIVILEGES closes that for the common case. It is keyed on
-- (creating role, schema, object type), so it covers objects created by the
-- role running this file. There is no FOR ANY ROLE form: if a later migration
-- is applied by a different superuser, its tables are uncovered again.
--
-- Hence the house convention, which is load-bearing rather than pedantry:
-- A MIGRATION THAT CREATES A TABLE MUST STILL CARRY ITS OWN EXPLICIT GRANT.
-- Default privileges cover the common case; the explicit grant survives a role
-- mismatch.
ALTER DEFAULT PRIVILEGES IN SCHEMA orbit
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO orbit_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA orbit
    GRANT USAGE ON SEQUENCES TO orbit_app;

-- Append-only, enforced. The ordering matters — this must follow the blanket
-- grant — and note it is NOT covered by the default-privileges rule above:
-- that rule grants UPDATE and DELETE, and "append-only" is not something a
-- CREATE TABLE can express. Any future append-only table needs its own REVOKE
-- in the migration that creates it, or it will silently be writable.
REVOKE UPDATE, DELETE ON orbit.audit_log FROM orbit_app;

-- Assert rather than assume. A grant that silently failed to apply, or a later
-- edit that loosened the audit log, should stop the migration here rather than
-- be discovered when someone needs the trail.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'audit_log' AND privilege_type IN ('UPDATE', 'DELETE')
    ) THEN
        RAISE EXCEPTION 'orbit_app must not hold UPDATE or DELETE on orbit.audit_log';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'audit_log' AND privilege_type = 'INSERT'
    ) THEN
        RAISE EXCEPTION 'orbit_app must hold INSERT on orbit.audit_log';
    END IF;
END
$$;
