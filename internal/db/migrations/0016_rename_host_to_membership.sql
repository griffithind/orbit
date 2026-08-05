-- host -> membership.
--
-- The old name claimed the row was a machine. It is not: it is the join of a
-- machine and a mesh, and every reader has had to hold that correction in their
-- head. Now that device_id is NOT NULL (migration 0015) the row's definition is
-- literally "this device, in that network", and the name can say so.
--
-- WHY A RENAME AND NOT A NEW TABLE. A rename is a catalogue update — no rows
-- move, no data is copied, and it cannot half-succeed. Creating a table and
-- migrating into it would take a full copy of the fleet and would leave two
-- tables in the schema for as long as anyone forgot to drop one.
--
-- Everything below is mechanical. Constraint and index names are renamed too,
-- because Postgres does NOT rename them with their table: leaving them would
-- mean an error message naming host_state_check on a table called membership,
-- which is exactly the kind of stale breadcrumb that costs an hour.

ALTER TABLE orbit.host RENAME TO membership;
ALTER TABLE orbit.host_address RENAME TO membership_address;

-- The foreign key column, everywhere it appears. Same reasoning as the table:
-- certificate.host_id on a table called membership reads as a different thing.
ALTER TABLE orbit.membership_address     RENAME COLUMN host_id TO membership_id;
ALTER TABLE orbit.certificate            RENAME COLUMN host_id TO membership_id;
ALTER TABLE orbit.enrollment_credential  RENAME COLUMN host_id TO membership_id;
ALTER TABLE orbit.control_plane          RENAME COLUMN host_id TO membership_id;

-- Constraints and indexes. IF EXISTS throughout: several of these were created
-- by later migrations and a database rebuilt from a different starting point
-- may legitimately lack one.
ALTER TABLE orbit.membership RENAME CONSTRAINT host_state_check TO membership_state_check;

ALTER INDEX IF EXISTS orbit.host_address_host_idx  RENAME TO membership_address_membership_idx;
ALTER INDEX IF EXISTS orbit.host_convergence_idx   RENAME TO membership_convergence_idx;
ALTER INDEX IF EXISTS orbit.host_device_id_idx     RENAME TO membership_device_id_idx;
ALTER INDEX IF EXISTS orbit.host_network_state_idx RENAME TO membership_network_state_idx;
ALTER INDEX IF EXISTS orbit.host_pending_idx       RENAME TO membership_pending_idx;
ALTER INDEX IF EXISTS orbit.host_role_idx          RENAME TO membership_role_idx;

--------------------------------------------------------------------------------
-- GRANTS
--------------------------------------------------------------------------------
--
-- A rename carries privileges with it — they are attached to the object, not the
-- name — so nothing needs regranting. Asserted rather than assumed, because the
-- failure mode is identical to the one 0011 warns about: it surfaces at RUNTIME
-- on the first request, not here.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'membership' AND privilege_type = 'INSERT'
    ) THEN
        RAISE EXCEPTION 'orbit_app lost INSERT on orbit.membership across the rename';
    END IF;
END
$$;

-- And the old names are gone, so nothing can still be reading them.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
         WHERE table_schema = 'orbit' AND table_name IN ('host', 'host_address')
    ) THEN
        RAISE EXCEPTION 'orbit.host still exists after the rename';
    END IF;
END
$$;
