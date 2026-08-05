-- Device identity: the first thing in this schema that is NOT scoped to a
-- network.
--
-- WHAT A DEVICE IS.
--
-- A physical machine, identified by a keypair it generated itself at first
-- start — before it had joined anything and before it had heard of a control
-- plane. Nobody issues it, nothing expires it, and it is the same key across
-- every network this machine joins and every control plane it talks to.
--
-- That "nobody issues it" is the entire point, and it is why the table exists
-- rather than another column on orbit.host.
--
-- WHY, IN ONE PARAGRAPH.
--
-- The agent surface is reachable only over the overlay, so a host needs a
-- working tunnel to renew the certificate that gives it a working tunnel;
-- `orbit agent recover` exists solely to break that circle. Giving the host a
-- second, longer-lived issued certificate only moves the problem — two expiring
-- credentials still both expire. An identity that is never issued and never
-- expires cannot fail that way, so a host can always reach the control plane,
-- and a host whose data plane is broken can finally report that its data plane
-- is broken. See docs/design-device-identity.md.
--
-- RELATIONSHIP TO orbit.host.
--
-- A device has many hosts: one per network it has joined. A host is therefore
-- "this device, in that network", which is what it always meant informally.
-- Every other per-host table keys on (network_id, host_id) deliberately; this
-- one sits above that, which is why it does not.

CREATE TABLE orbit.device (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- SHA-256 of the raw device public key, hex. The natural key.
    --
    -- UNIQUE because two rows for one key would mean two answers to "is this
    -- machine blocked", and the wrong one would eventually be read. It is also
    -- the lookup index: every mTLS connection resolves a device by this.
    --
    -- Hex rather than bytea for the same reason orbit.ca stores a fingerprint
    -- as text: it appears in logs, in the CLI, and in support conversations,
    -- and a value an operator can paste back is worth the few extra bytes.
    key_fingerprint text NOT NULL UNIQUE,

    -- The raw public key, in the encoding the host presented. Kept because a
    -- fingerprint proves a match but cannot verify a signature, and issuing a
    -- device certificate needs the key itself.
    public_key bytea NOT NULL,

    -- What the key is held in, as the host claims: 'file' or 'token'.
    --
    -- Advisory unless backed by attestation, and named so. A file-held key is
    -- copyable off a disk image; a token-held one is not. Recording the claim
    -- lets an operator see the difference across a fleet before there is
    -- attestation to prove it, and lets policy require the stronger one later.
    key_backing text NOT NULL DEFAULT 'file'
        CHECK (key_backing IN ('file', 'token')),

    -- Free-text, host-supplied, never trusted for anything. Present so a
    -- pending join is identifiable by a human deciding whether to authorize it:
    -- "which of these rows is the laptop on my desk" is otherwise unanswerable.
    hostname text CHECK (hostname IS NULL OR length(hostname) <= 253),

    -- BLOCKING. This is the revocation mechanism, and it is why the device
    -- certificate can safely be long-lived.
    --
    -- Nebula's blocklist is expensive because it must reach every node, which
    -- is why short certificate lifetimes are the revocation story for mesh
    -- membership. This is the opposite: there is exactly ONE enforcement point
    -- and it is the process holding this database, so a check here is a lookup
    -- it is already making. Revocation is immediate, with no propagation.
    --
    -- Blocking a DEVICE blocks it on this control plane across every network.
    -- Blocking a HOST blocks one membership. Both are useful; they are not the
    -- same action, and orbit.host.state stays the place for the second.
    blocked_at timestamptz,
    blocked_reason text CHECK (blocked_reason IS NULL OR length(blocked_reason) <= 512),

    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now()
);

-- A device's memberships.
--
-- NULLABLE HERE, AND IT MUST NOT STAY THAT WAY.
--
-- The target is NOT NULL: a membership exists BECAUSE a device joined, so "this
-- device, in that network" is the row's definition rather than a description of
-- it (docs/model.md §5, invariant 1). A nullable column leaves "which machine is
-- this" unanswerable for some rows — the exact question this table exists to
-- answer — and every read needs a nil branch with no correct behaviour.
--
-- It is nullable in THIS migration only because nothing creates a membership
-- with a device yet. `POST /v1/hosts` pre-creates a host before any device is
-- known, so a NOT NULL column here would make host creation fail at runtime
-- while every local test kept passing — migrations are tracked by name, so an
-- already-migrated database would never re-run this file and never notice.
--
-- The constraint tightens in the migration that lands the join path, which is
-- step 4 of the sequence in docs/model.md §6. That ordering is the whole point
-- of the sequence: it is the one step that cannot come early.
--
-- ON DELETE RESTRICT, not CASCADE and not SET NULL. Deleting a device that
-- still holds memberships is almost always a mistake — the memberships are what
-- give it reach — so the caller has to remove them first and see how many there
-- were. CASCADE would silently take the fleet's memory of them with it.
ALTER TABLE orbit.host
    ADD COLUMN device_id uuid REFERENCES orbit.device (id) ON DELETE RESTRICT;

-- The FK needs its own index; Postgres does not create one. Without it every
-- DELETE or UPDATE of a device primary key sequentially scans orbit.host.
CREATE INDEX host_device_id_idx ON orbit.host (device_id);

-- Finding a device's memberships across networks — "where is this laptop" — is
-- the query an operator runs when a machine is lost, and it is the one that
-- precedes blocking it.
CREATE INDEX device_blocked_at_idx ON orbit.device (blocked_at) WHERE blocked_at IS NOT NULL;

--------------------------------------------------------------------------------
-- GRANT
--------------------------------------------------------------------------------
--
-- This migration creates a table, so it carries its own grant. 0002 explains
-- why that is a house rule: the blanket GRANT ... ON ALL TABLES there was
-- evaluated once and is not a standing rule, and the ALTER DEFAULT PRIVILEGES
-- backing it is keyed on the creating role — so a migration applied by a
-- different superuser would leave this table with no grant, and the omission
-- surfaces at RUNTIME on the join path rather than here.
--
-- UPDATE is required: last_seen_at is refreshed on every contact, and blocking
-- sets blocked_at. DELETE is required to forget a decommissioned machine.
GRANT SELECT, INSERT, UPDATE, DELETE ON orbit.device TO orbit_app;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'device' AND privilege_type = 'INSERT'
    ) THEN
        RAISE EXCEPTION 'orbit_app must hold INSERT on orbit.device';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'device' AND privilege_type = 'UPDATE'
    ) THEN
        RAISE EXCEPTION 'orbit_app must hold UPDATE on orbit.device';
    END IF;
END
$$;

-- Assert the column that must never exist.
--
-- A private key column on this table is not something anyone would add on
-- purpose. It is what gets added while making enrollment "simpler" — generate
-- the device key server-side, hand it to the host, skip a round trip — and it
-- is invisible in review because a key column on a device table looks
-- reasonable.
--
-- It would destroy the one property this design rests on: that the control
-- plane can mint a certificate for a host but can never impersonate one,
-- because it has never seen the private half. A tripwire, not a constraint — a
-- later migration can of course add it, but whoever does has to delete this
-- block first, and read why.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'orbit' AND table_name = 'device'
           AND column_name IN ('private_key', 'secret_key', 'key_pem')
    ) THEN
        RAISE EXCEPTION
            'orbit.device must never hold private key material: a control plane '
            'that can read a device key can impersonate the device';
    END IF;
END
$$;
