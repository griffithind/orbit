-- The network identity key, and the network ID derived from it.
--
-- WHAT THIS BUYS.
--
-- Until now a machine joined by naming a network uuid or slug and a URL, and
-- nothing in either one said which control plane to expect. Pointing a machine
-- at a hostile URL worked: it would join, be issued a certificate by somebody
-- else's CA, and be on somebody else's mesh.
--
-- A network ID is 80 bits of SHA-256 over an Ed25519 public key, in Crockford
-- base32 — `p8k3zj9x2mq4wr7t`. It is a COMMITMENT TO A TRUST ANCHOR rather than
-- a label: a joining machine checks that the control plane answering both serves
-- the key the ID names AND can sign with its private half. See
-- internal/ca/networkid.go and docs/design-device-identity.md §4.
--
-- NOT DERIVED FROM THE CA KEY, which was the first design and is wrong. Orbit
-- rotates CAs, so an ID derived from the active CA would change on every
-- rotation — every machine's stored ID becoming wrong at once. This key is
-- generated at bootstrap, never rotated, and never signs a certificate.
--
-- WHY THE WIPE.
--
-- These columns are NOT NULL because a network without a verifiable ID is a
-- network that cannot be safely joined, and a nullable column here would mean
-- every join carries a branch for "this one cannot be checked" — which is the
-- branch an attacker wants.
--
-- An identity keypair cannot be generated in SQL, so existing rows cannot be
-- back-filled. They are deleted. That is safe here and would not be on a
-- deployed system: this is pre-1.0, the only networks in existence are on test
-- machines, and `orbitd bootstrap` recreates one in a second. On a real
-- deployment this would be an operator decision with a migration tool, not a
-- DELETE in a schema migration.
--
-- Deleting a network cascades to its CAs, roles, memberships, addresses,
-- certificates, credentials and blocklist entries. Devices are NOT deleted:
-- a device is a machine, it is not scoped to a network, and every machine
-- re-presenting its key gets the same row back. Its posture history survives the
-- rebuild, which is the correct behaviour and a small demonstration of why the
-- device noun is separate.

--------------------------------------------------------------------------------
-- First, a bug this migration's DELETE exposed.
--------------------------------------------------------------------------------
--
-- Migration 0014 gave orbit.enrollment_credential a COMPOSITE foreign key —
-- (network_id, reserved_role_id) -> orbit.role — with ON DELETE SET NULL. That
-- reads as "if the reserved role goes away, forget the role", and it is not what
-- it does: SET NULL on a composite key nulls EVERY column in it, including
-- network_id, which is NOT NULL. So deleting a role that any live reservation
-- named would fail with a constraint violation naming a column the operator
-- never touched.
--
-- Nothing had ever deleted a role with a reservation against it, so it sat
-- unnoticed until the DELETE below cascaded through roles. The fix is Postgres
-- 15's column-list form, which nulls only the column meant: a reservation whose
-- role is deleted survives and grants no role, which is exactly what a
-- reservation with no role does anyway.
ALTER TABLE orbit.enrollment_credential
    DROP CONSTRAINT enrollment_credential_role_fk;

ALTER TABLE orbit.enrollment_credential
    ADD CONSTRAINT enrollment_credential_role_fk
        FOREIGN KEY (network_id, reserved_role_id)
        REFERENCES orbit.role (network_id, id)
        ON DELETE SET NULL (reserved_role_id);

--------------------------------------------------------------------------------
-- Now the wipe.
--------------------------------------------------------------------------------

-- TRUNCATE ... CASCADE rather than DELETE, and the difference is not style.
--
-- A DELETE relies on the cascade reaching every dependent row in an order the
-- foreign keys permit, and they do not: orbit.certificate references both a
-- membership and a CA, and the CA reference is not ON DELETE CASCADE — so
-- deleting a network removes its CAs while certificates still point at them, and
-- the delete fails on a constraint that names two tables the operator never
-- mentioned.
--
-- TRUNCATE CASCADE empties the whole referencing closure in one statement, with
-- no ordering to get right. It reaches network, ca, role, membership,
-- membership_address, certificate, enrollment_credential, blocklist_entry and
-- control_plane.
--
-- It deliberately does NOT reach orbit.device, which references nothing here,
-- or orbit.audit_log and orbit.api_token. Devices survive because a device is a
-- machine and machines did not stop existing; each one re-presenting its key
-- gets its row, and its posture history, back. The audit log survives because
-- the record of what was done is the last thing a rebuild should erase.
TRUNCATE orbit.network CASCADE;

ALTER TABLE orbit.network
    -- The Ed25519 public key, raw (32 bytes). Handed to a joining machine so it
    -- can check the ID and verify the proof.
    ADD COLUMN identity_public_key bytea NOT NULL
        CHECK (length(identity_public_key) = 32),

    -- The derived ID. Stored rather than computed on read: it is a lookup key —
    -- `orbit agent join p8k3zj9x2mq4wr7t` resolves through it — and an index on
    -- a function of a column would have to be kept in step with the derivation
    -- in Go. Deriving in two places is how they come to disagree.
    --
    -- UNIQUE across the whole control plane, not per anything: two networks
    -- sharing an ID would make the ID useless for resolution, and it can only
    -- happen through a SHA-256 collision or a copied key.
    ADD COLUMN network_id text NOT NULL UNIQUE
        CHECK (network_id ~ '^[0-9abcdefghjkmnpqrstvwxyz]{16}$'),

    -- Where the private half lives, in the same opaque-locator form
    -- orbit.ca.signer_ref uses: file://…, and one day awskms://… or pkcs11://…
    --
    -- NEVER the key itself. Someone holding this key can convince a JOINING
    -- machine that their control plane is this network — they still cannot mint
    -- certificates for the existing fleet, which needs the CA key — and that is
    -- close enough to full compromise to warrant the same custody. The assertion
    -- below is what stops it being stored here for convenience.
    ADD COLUMN identity_signer_ref text NOT NULL;

-- The lookup a join makes.
--
-- The UNIQUE constraint above already creates an index, so this is a comment
-- rather than a second index: resolution by network ID is served by it.

--------------------------------------------------------------------------------
-- The tripwire
--------------------------------------------------------------------------------
--
-- Same shape as the one on orbit.device, and for the same reason. A private-key
-- column on a network table is not something anyone adds on purpose; it is what
-- gets added while making bootstrap "simpler" — store the identity key beside
-- the public one, skip the file, skip the passphrase — and it is invisible in
-- review because a key column on a network table looks reasonable.
--
-- It would put the key that lets an attacker impersonate this network to every
-- future machine in the same place as the data an application-level SQL flaw can
-- read. A later migration can of course add it, but whoever does has to delete
-- this block first, and read why.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'orbit' AND table_name = 'network'
           AND column_name IN ('identity_private_key', 'identity_key', 'identity_key_pem')
    ) THEN
        RAISE EXCEPTION
            'orbit.network must never hold the network identity private key: a '
            'control plane that can read it from the database can be impersonated '
            'to every machine that joins afterwards';
    END IF;
END
$$;
