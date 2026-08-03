-- A host's role must belong to the host's own network.
--
-- 0001 wrote:
--
--     role_id uuid REFERENCES orbit.role (id) ON DELETE SET NULL
--
-- with no network component. orbit.role is per-network — it is keyed on
-- (network_id, name) and cascades from orbit.network — but the reference from
-- orbit.host names a role by id alone, so any role in the deployment satisfies
-- it. Nothing in Go closes the gap either: internal/api/admin.go parses
-- role_id, internal/store/host.go stores it, and neither compares
-- role.network_id against host.network_id.
--
-- That contradicts the schema header on two counts. "A network is the unit of
-- separation ... Nothing crosses between them" is not true of role assignment,
-- and "invariants that protect correctness live in the database, not in Go" is
-- not true here either — this one lived nowhere at all.
--
-- The consequence is not theoretical. internal/enroll/service.go renderFor
-- fetches the role by id and renders role.firewall_rules straight into the
-- host's config fragment. Assign network B's role to a host in network A and
-- B's firewall rules are written verbatim into A's host config. The groups half
-- of the role usually fails closed at issuance, because the CA rejects a group
-- it does not carry — but that is the CA saving us, not the schema, and it
-- stops saving us the moment two networks' CAs share a group name. The firewall
-- rules render either way. They never touch the CA.
--
-- Fixed here the way the schema already handles this shape elsewhere: widen the
-- referenced key to include the network, then reference it compositely.

--------------------------------------------------------------------------------

-- The target key for the composite reference. role.id is already unique on its
-- own, so this adds no new restriction on orbit.role — it exists solely so that
-- (network_id, id) is a referencable key, which a foreign key requires.
ALTER TABLE orbit.role
    ADD CONSTRAINT role_network_id_id_key UNIQUE (network_id, id);

-- The old reference is strictly weaker than the new one and would only
-- duplicate its ON DELETE action, so it goes.
--
-- Dropping it loses nothing. host.network_id is NOT NULL, so a row that
-- satisfies the composite constraint with a non-null role_id has matched a real
-- orbit.role row on (network_id, id) — and since id is the primary key, that is
-- a superset of what "role_id REFERENCES role (id)" asserted.
ALTER TABLE orbit.host
    DROP CONSTRAINT host_role_id_fkey;

ALTER TABLE orbit.host
    ADD CONSTRAINT host_role_same_network_fkey
    FOREIGN KEY (network_id, role_id)
    REFERENCES orbit.role (network_id, id)
    -- Preserves 0001's semantics: deleting a role unassigns it from its hosts
    -- rather than blocking the delete or taking the hosts with it.
    --
    -- The column list is required, not stylistic. A bare ON DELETE SET NULL on
    -- a composite foreign key nulls EVERY referencing column, and network_id is
    -- NOT NULL — so deleting a role would fail at run time with a not-null
    -- violation, on a delete that used to work. Naming role_id confines it.
    -- (PostgreSQL 15+; docs/deployment.md's "Postgres 14+" needs updating, and
    -- the project has run 17 everywhere since.)
    ON DELETE SET NULL (role_id);

-- MATCH SIMPLE, and that is the behaviour we want.
--
-- A foreign key with no MATCH clause is MATCH SIMPLE, which is satisfied
-- whenever ANY referencing column is NULL — the whole constraint is skipped,
-- no lookup happens. network_id is NOT NULL, so the only column that can be
-- NULL is role_id, and therefore:
--
--   role_id IS NULL      -> constraint satisfied, no role required.
--   role_id IS NOT NULL  -> both columns non-null, full check applies, and the
--                           role must exist IN THIS HOST'S NETWORK.
--
-- "A host may have no role" is preserved exactly. Note that MATCH FULL would
-- have been wrong here: it demands all-or-nothing across the columns, so with
-- network_id always populated it would reject every host without a role.
--
-- Confirmed against the live schema: an unassigned host inserts fine, a
-- same-network role is accepted, a cross-network role is rejected with 23503.

-- Supports the ON DELETE SET NULL scan. Without it, deleting a role sequentially
-- scans orbit.host; there was no index on role_id before this migration either,
-- so this is a fix carried along with the constraint that depends on it.
CREATE INDEX host_role_idx ON orbit.host (network_id, role_id);

COMMENT ON CONSTRAINT host_role_same_network_fkey ON orbit.host IS
    'A host may only be assigned a role from its own network. Enforced here rather than in Go: a concurrent request can race an application-layer check, and the cost of losing is another network''s firewall rules rendered into this host''s config.';
