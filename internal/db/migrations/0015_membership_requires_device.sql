-- A membership cannot exist without a device.
--
-- This is docs/model.md §5 invariant 1, and it is the point of the whole
-- sequence. A membership is "this device, in that network" — that is its
-- DEFINITION, not a description of it — so a row that names no machine is not a
-- partially-filled membership, it is a row that means nothing. Every read of
-- device_id has until now needed a nil branch with no correct behaviour.
--
-- WHY THIS COULD NOT LAND EARLIER.
--
-- Migrations are tracked by name with no checksum, so an already-migrated
-- database never re-runs a file. Adding NOT NULL while POST /v1/hosts still
-- existed would have left every local test green — their databases were already
-- past 0011 — while a fresh deployment failed at the first host creation. The
-- endpoint had to go first (migration 0014 and step 3), and it has.
--
-- WHAT CREATES A MEMBERSHIP NOW, exhaustively:
--
--   Tx.JoinNetwork               a device asks; pending until authorized
--   Tx.CreateReservedMembership  a device redeems a reservation
--   Service.SelfIssue            the control plane's own row, on its own device
--
-- All three take a device. There is no fourth, and this constraint is what keeps
-- it that way.

-- Anything left from before is a row nothing can identify: it was created by an
-- endpoint that no longer exists, for a machine that never arrived or that
-- enrolled with a code under the old model. There is no key to attach and no
-- way to invent one — the whole property being established is that the control
-- plane cannot invent a device identity — so these are deleted rather than
-- back-filled.
--
-- Safe because there is no deployment: this is pre-1.0 and the tree's own tests
-- rebuild their fixtures. On a live system this block would be an operator
-- decision, not a migration.
DELETE FROM orbit.host WHERE device_id IS NULL;

ALTER TABLE orbit.host
    ALTER COLUMN device_id SET NOT NULL;

-- The columns that moved to orbit.device (migration 0013).
--
-- They are properties of a MACHINE, not of a machine's presence in a network. A
-- laptop on three meshes has one agent version and one nebula version; keeping
-- them here meant three rows, three chances to disagree, and no answer to "what
-- is this machine running" that did not involve picking one.
--
-- last_seen_at is the interesting one and is worth being precise about, because
-- it looks like it belongs to both. It does not: it conflated two facts.
--
--   "this DEVICE is talking to the control plane"  -> orbit.device.last_seen_at
--   "this MEMBERSHIP's tunnel is up"               -> not this column, and not
--                                                     yet modelled
--
-- A laptop online but partitioned from one of its networks is a real situation,
-- and it is exactly the one worth alerting on. The old column could not express
-- it: the agent reports over the overlay, so a partitioned membership simply
-- went quiet and looked identical to a closed laptop. Dropping it removes an
-- answer that was wrong rather than one that was useful; the per-membership
-- liveness signal has to come from somewhere that can actually observe it.
ALTER TABLE orbit.host
    DROP COLUMN last_seen_at,
    DROP COLUMN nebula_version,
    DROP COLUMN agent_version;

-- Assert the invariant this migration exists to establish, so a future ALTER
-- that relaxes it has to delete this block and read why.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'orbit' AND table_name = 'host'
           AND column_name = 'device_id' AND is_nullable = 'YES'
    ) THEN
        RAISE EXCEPTION
            'orbit.host.device_id must be NOT NULL: a membership is "this device '
            'in that network", so a row naming no machine means nothing';
    END IF;
END
$$;
