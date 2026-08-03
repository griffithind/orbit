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

REVOKE UPDATE, DELETE ON orbit.audit_log FROM orbit_app;
