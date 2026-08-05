-- Device facts and posture: what a machine IS, recorded once per machine.
--
-- WHY THESE MOVE OFF orbit.host.
--
-- A laptop on three networks has one disk-encryption state, not three. On the
-- host table the agent would report it per-membership: three rows, three chances
-- to disagree, and no answer to "is this laptop encrypted" that does not involve
-- picking one of them. Every column below is a property of the machine and of
-- nothing else, which is the rule in docs/model.md §2 — a fact belongs to the
-- narrowest noun that determines it.
--
-- THE SHAPE: TYPED COLUMNS, NOT A DOCUMENT.
--
-- docs/model.md §8 left this open. It is settled here as columns, and the
-- deciding argument is what reads them. Posture exists to feed policy, and
-- policy compiles SERVER-SIDE to addresses (internal/policy) — so a posture
-- predicate becomes a WHERE clause over the fleet on every compile. Columns make
-- that an indexable query; a jsonb document makes it a traversal per row, and
-- turns a typo in a policy selector into a silent no-match instead of an error.
--
-- The cost is real and worth naming: every new posture signal is a migration.
-- That is acceptable because the set is small and slow-moving — it tracks what
-- an agent can actually read natively — and unacceptable-looking flexibility is
-- how a schema ends up with a jsonb column nobody can query.
--
-- TRI-STATE, AND THIS IS THE PART THAT IS EASY TO GET WRONG.
--
-- Every posture column is a NULLABLE boolean, and NULL means "the agent could
-- not determine this", NOT "false". They are different in the direction that
-- matters: a machine whose disk encryption could not be read is not a machine
-- with an unencrypted disk, and a policy that treated it as one would cut off a
-- working fleet the day a probe broke. A policy that wants to refuse unknowns
-- must say so; it must not get there by accident.

ALTER TABLE orbit.device
    -- Facts. Descriptive, host-supplied, and never an authorization input on
    -- their own — an agent can claim any kernel version it likes.
    ADD COLUMN os              text CHECK (os IS NULL OR length(os) <= 64),
    ADD COLUMN os_version      text CHECK (os_version IS NULL OR length(os_version) <= 128),
    ADD COLUMN kernel          text CHECK (kernel IS NULL OR length(kernel) <= 128),
    ADD COLUMN arch            text CHECK (arch IS NULL OR length(arch) <= 32),
    ADD COLUMN agent_version   text CHECK (agent_version IS NULL OR length(agent_version) <= 64),
    ADD COLUMN nebula_version  text CHECK (nebula_version IS NULL OR length(nebula_version) <= 64),

    -- Posture. NULL is unknown; see above.
    ADD COLUMN disk_encrypted   boolean,
    ADD COLUMN secure_boot      boolean,
    ADD COLUMN firewall_enabled boolean,
    ADD COLUMN tpm_present      boolean,

    -- ONE timestamp per group rather than one per column.
    --
    -- The agent reads each group in a single pass, so the fields in a group
    -- really are observed together and N timestamps would be N copies of one
    -- fact. Partial reads — the probe for one signal failing while the others
    -- succeed — are expressed by that signal being NULL, which is what the
    -- tri-state is for. The two questions an operator asks are "how old is this
    -- reading" and "which signals came back", and this shape answers both
    -- without a column per answer.
    ADD COLUMN facts_observed_at   timestamptz,
    ADD COLUMN posture_observed_at timestamptz;

-- The fleet-wide posture question — "which machines are unencrypted, or have
-- not told us" — is the one an operator runs, and it is the one a policy
-- compiles. Partial on the interesting side: a fleet is mostly compliant, so
-- indexing the compliant majority would cost writes to answer nothing.
CREATE INDEX device_posture_gap_idx ON orbit.device (last_seen_at)
    WHERE disk_encrypted IS NOT TRUE
       OR secure_boot IS NOT TRUE;

-- Stale posture is its own question and a different one: a reading from six
-- months ago is not evidence about a machine today, and CISA's maturity ladder
-- turns on *continuously* verified rather than verified once.
CREATE INDEX device_posture_observed_idx ON orbit.device (posture_observed_at NULLS FIRST);

-- The tripwire in 0011 asserts orbit.device holds no private key material.
-- Re-assert it here, because this migration is the first one to ADD columns to
-- that table and the natural place for someone to add "just one more field".
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
