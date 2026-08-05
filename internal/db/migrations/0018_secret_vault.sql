-- Private keys in Postgres, encrypted under a key that is not in Postgres.
--
-- THE PROBLEM THIS SOLVES IS OPERATIONAL, NOT CRYPTOGRAPHIC.
--
-- A CA signing key on one machine's disk is a defensible posture. It stops being
-- one the moment there is a second machine: adding a replica meant copying every
-- network's CA key and identity key by hand, keeping them in step through every
-- CA rotation, with nothing to detect drift. A replica holding a stale key does
-- not fail at startup — it fails when somebody is trying to add a machine.
--
-- THE PROPERTY THAT MUST SURVIVE.
--
--   Read access to this database does not let an attacker mint a certificate.
--
-- It survives exactly. The ciphertext is here; the key encryption key is not,
-- and lives where the CA key used to — on the control-plane host, in an
-- environment variable or a TPM-sealed credential. An attacker needed
-- (database read) + (file on the host); they now need (database read) + (the
-- KEK, on the host). Same two factors, same hosts.
--
-- What changes is the count: one secret per deployment instead of N files per
-- network. See docs/key-custody.md §4.1 and internal/secrets.

--------------------------------------------------------------------------------
-- The KEK's salt and verifier
--------------------------------------------------------------------------------
--
-- Exactly one row, ever. A second would mean two derivations of "the" KEK and no
-- way to tell which secrets were sealed under which — so the primary key is a
-- constant and the CHECK makes that explicit rather than conventional.
CREATE TABLE orbit.kek (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),

    -- Argon2id salt. NOT secret: its job is to make the derivation specific to
    -- this deployment, so the same passphrase used for two Orbits yields two
    -- unrelated keys. Storing it beside the ciphertext is correct and is why
    -- there is no third thing for an operator to distribute.
    salt bytea NOT NULL CHECK (length(salt) = 16),

    -- A known plaintext sealed under the KEK, so a start with the wrong
    -- passphrase fails HERE rather than at the first signing operation.
    --
    -- Worth the two columns. Without it, a replica with a mistyped passphrase
    -- starts cleanly, serves reads, and fails the first time somebody adds a
    -- machine — which is the worst moment to discover it and the hardest to
    -- attribute to a configuration mistake made days earlier.
    verifier_nonce      bytea NOT NULL,
    verifier_ciphertext bytea NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now()
);

--------------------------------------------------------------------------------
-- The secrets
--------------------------------------------------------------------------------

CREATE TABLE orbit.secret (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- What this key is for: 'ca_signing_key' or 'network_identity_key'.
    --
    -- Bound into the AEAD's additional data, not merely stored. An attacker with
    -- database WRITE could otherwise move a network identity key into a CA's row
    -- — both are Ed25519, both parse — and have the control plane sign
    -- certificates with a key whose custody rules are weaker. With the kind
    -- authenticated, a relabelled row fails to decrypt instead.
    kind text NOT NULL CHECK (kind IN ('ca_signing_key', 'network_identity_key')),

    -- XChaCha20-Poly1305. The 24-byte nonce is random per row: at 192 bits it
    -- cannot realistically repeat, so there is no counter to keep and no way for
    -- two replicas encrypting at once to collide.
    nonce      bytea NOT NULL CHECK (length(nonce) = 24),
    ciphertext bytea NOT NULL,

    -- The network this belongs to, when it belongs to one. Both current kinds
    -- do; the column is nullable so a future deployment-wide secret does not
    -- need a schema change to be storable.
    --
    -- ON DELETE CASCADE: a network's keys are meaningless once the network is
    -- gone, and leaving them would be ciphertext nobody can attribute.
    network_id uuid REFERENCES orbit.network (id) ON DELETE CASCADE,

    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX secret_network_idx ON orbit.secret (network_id, kind);

--------------------------------------------------------------------------------
-- GRANT
--------------------------------------------------------------------------------
--
-- Both tables are created here, so this migration carries its own grants — the
-- house rule from 0002, because ALTER DEFAULT PRIVILEGES is keyed on the
-- creating role and a migration applied by a different superuser would otherwise
-- leave these ungranted, surfacing at RUNTIME on the first signing operation.
--
GRANT SELECT, INSERT, UPDATE, DELETE ON orbit.secret TO orbit_app;
GRANT SELECT, INSERT ON orbit.kek TO orbit_app;

-- REVOKE, not merely a narrower GRANT.
--
-- 0002 set ALTER DEFAULT PRIVILEGES for orbit_app on every table created in this
-- schema, which includes DELETE — so granting only SELECT and INSERT above adds
-- nothing and removes nothing. The table arrives deletable.
--
-- That matters here and nowhere else: deleting the kek row orphans every secret
-- in the database irreversibly, and no operation wants it. The assertion below
-- was written expecting the GRANT to be sufficient and failed on the first run,
-- which is the only reason this REVOKE exists rather than a comment claiming the
-- grant was enough.
REVOKE DELETE, TRUNCATE ON orbit.kek FROM orbit_app;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'secret' AND privilege_type = 'INSERT'
    ) THEN
        RAISE EXCEPTION 'orbit_app must hold INSERT on orbit.secret';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'kek' AND privilege_type = 'DELETE'
    ) THEN
        RAISE EXCEPTION
            'orbit_app must NOT hold DELETE on orbit.kek: dropping that row '
            'orphans every stored secret and cannot be undone';
    END IF;
END
$$;

--------------------------------------------------------------------------------
-- The tripwire, restated for the table that now legitimately holds ciphertext
--------------------------------------------------------------------------------
--
-- orbit.secret is the one table in this schema that holds key material at all,
-- which makes it the obvious place to "just add a plaintext column" while
-- debugging. It would silently undo the only property the design rests on.
--
-- A later migration can of course add one. Whoever does has to delete this block
-- first, and read why.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'orbit' AND table_name = 'secret'
           AND column_name IN ('plaintext', 'private_key', 'key_pem', 'unsealed')
    ) THEN
        RAISE EXCEPTION
            'orbit.secret must hold ciphertext only: a plaintext column here '
            'makes database read access sufficient to mint certificates, which '
            'is the one thing envelope encryption exists to prevent';
    END IF;
END
$$;
