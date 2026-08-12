-- Per-code attempt limiting, so a code cannot be guessed at indefinitely.
--
-- The enrollment limiter is per SOURCE ADDRESS and per PROCESS: a field on
-- Server backed by a plain map, so N replicas give N times the deployment-wide
-- ceiling, and nothing counts failures against a CODE at all. internal/api's
-- own comment says so — "Nothing finer is available". This is the finer thing.
--
-- A separate migration rather than an edit to 0001_initial.sql, deliberately.
-- `orbitd serve` now compares the applied migration set to the embedded one BY
-- NAME (ADR-0026), so editing 0001 in place would leave an already-migrated
-- database recording a name it still matches while holding a schema it no
-- longer has — a green check over a stale database, which is the exact failure
-- that check exists to catch.

ALTER TABLE orbit.enrollment_credential
    ADD COLUMN failed_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN locked_at timestamptz;

-- The application counts failures and reads the lock; it does not clear either.
-- Unlocking is minting a new code, which is one round trip for an operator and
-- removes any path where a caller can reset its own budget.
GRANT SELECT, UPDATE ON TABLE orbit.enrollment_credential TO orbit_app;
