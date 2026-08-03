-- The network policy document, versioned, and the switch that puts it in force.
--
-- WHAT THIS IS FOR. Orbit expresses firewall policy per ROLE: orbit.role
-- holds firewall_rules, and every host carrying that role renders them. That
-- works, and it stays. What it cannot express is a rule about a SET OF HOSTS
-- that is not a role — "the database tier accepts 5432 from the web tier" — and
-- the workaround for that is a certificate group, which means an edit is a
-- reissuance. A group lives inside the signed certificate, so adding one costs
-- every affected host a certificate lifetime before the change is in force
-- (see role.groups_changed_at, migration 0004).
--
-- The policy document is the alternative: one document per network, compiled by
-- the control plane into per-host rules by resolving selectors to member
-- ADDRESSES rather than to groups. Addresses are already in the rendered
-- configuration, so an edit is config-only and converges on the next poll —
-- seconds, with no certificate reissued and nothing to wait out.
--
--------------------------------------------------------------------------------
-- WHY A TABLE WITH HISTORY, AND NOT A COLUMN ON orbit.network
--------------------------------------------------------------------------------
--
-- A column would have been less code. Three things argue against it, and the
-- third is the one that decides it.
--
--   * "What did the policy say last Tuesday" is a question an incident asks,
--     and it is asked about the firewall more often than about anything else
--     here — the whole point of a policy document is that it is edited casually
--     and fleet-wide, which is exactly the combination that produces "when did
--     this stop working, and what changed". A column answers with the present
--     tense only.
--
--   * orbit.audit_log could carry the document in `meta` instead, and it is
--     already append-only and already records who and when. But reconstructing
--     a document by scanning audit metadata is the shape orbit.role explicitly
--     rejected for group changes (see ActionRoleGroupsChanged in
--     store/network.go): the answer an incident needs should be a WHERE clause
--     against a column, not a scan through JSON that happens to have the value
--     in it. The audit entry still exists and still records the ACTION; this
--     table records the DOCUMENT, and they answer different questions.
--
--   * A document is small — kilobytes — and edits are rare compared with every
--     other write this schema takes. Keeping every version costs approximately
--     nothing, and there is no version of "we should have kept it" that can be
--     satisfied after the fact.
--
--------------------------------------------------------------------------------
-- WHY jsonb, AND WHAT IT COSTS
--------------------------------------------------------------------------------
--
-- The load-bearing property is that a re-send of an UNCHANGED document must
-- write nothing and bump no epoch. A config epoch bump wakes every agent in the
-- network to fetch and re-render, so a reconcile loop that re-applies the same
-- desired state every ten minutes would otherwise be fleet-wide work forever —
-- the same argument RoleChange.Changed and UpdateNetworkInstanceDefaults make,
-- and the reason both compare in SQL rather than in Go.
--
-- jsonb gives that structurally: Postgres normalizes on input (keys sorted,
-- whitespace gone, duplicate keys dropped) so `=` IS the semantic comparison,
-- and a client that re-sends the same policy with different key order or
-- indentation is correctly recognised as changing nothing. A text column would
-- have needed a ::jsonb cast at every comparison site, which is a rule a future
-- writer can forget; a bytes comparison in Go would call a reformat an edit.
--
-- THE COST, stated plainly: the stored document is not byte-identical to what
-- was sent. Key order and formatting do not survive, so `orbit policy show`
-- cannot hand back the exact file that was applied. That is accepted, and it is
-- arguably the better half of the trade — it means two operators who wrote the
-- same policy differently store the same document, and it means a version in
-- this table NEVER differs from its predecessor by whitespace alone. A history
-- where consecutive versions can be semantically identical is a history nobody
-- can read.

CREATE TABLE orbit.network_policy (
    network_id uuid NOT NULL REFERENCES orbit.network (id) ON DELETE CASCADE,

    -- Per network, starting at 1, assigned by the writer under the network row
    -- lock (store.PutPolicy). Not a global sequence: the version an operator
    -- quotes during an incident should be small and should mean something about
    -- THIS network, and a shared sequence makes "version 4013" of a network that
    -- has been edited twice.
    version bigint NOT NULL CHECK (version > 0),

    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),

    -- The config epoch this version produced.
    --
    -- Recorded because it is the only join between a policy version and what a
    -- host reported running. A host says applied_config_epoch = 41; the policy
    -- it was actually enforcing is the greatest version here with
    -- config_epoch <= 41. Without this column that question is unanswerable —
    -- timestamps do not line up with epochs, because an epoch also advances for
    -- a CA, a blocklist entry, and a topology change.
    config_epoch bigint NOT NULL CHECK (config_epoch > 0),

    -- Who wrote it, as they were named at the time. Captured rather than joined,
    -- for the reason audit_log.actor_display is captured: the record has to stay
    -- legible after the token is deleted.
    author text,

    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (network_id, version)
);

-- No separate index. Every read is either "the current version" or "the version
-- in force at time T", and both are a backwards scan of the primary key within
-- one network_id — which the PK's btree serves directly. An index on created_at
-- would be a second structure for a query the first one already answers.

--------------------------------------------------------------------------------
-- THE SWITCH
--------------------------------------------------------------------------------
--
-- A network draws its firewall from ONE source. Not both, and the reason is the
-- whole argument for authoritative config mode restated.
--
-- Nebula's firewall is allow-only: there is no deny rule, and rules from
-- separate config files CONCATENATE (nebula merges a config directory with
-- mergo.WithAppendSlice — see the config_mode column added in 0008). So two
-- sources of firewall rules can only ever ADD reachability, and the effective
-- policy is their union. What Orbit could then honestly report about a host is a
-- lower bound, presented as an answer.
--
-- That is exactly the defect config_mode = 'authoritative' exists to remove, and
-- reintroducing it here would be worse than fragment mode rather than equal to
-- it: in fragment mode the API says the policy it reports is incomplete, while
-- here the divergence would arrive wearing authoritative mode's guarantee.
--
-- So: 'role' or 'policy', and nothing renders both.
--
-- ROLES ARE NOT OBSOLETE IN POLICY MODE. Only the firewall half moves. A role
-- still carries `groups`, groups are still embedded in the signed certificate,
-- and the CA still constrains them. This column is named firewall_source rather
-- than something broader precisely so that stays visible.
--
-- role.firewall_rules is NOT dropped or emptied when a network switches. An
-- operator's rules are their data, switching is meant to be reversible, and a
-- mode change that silently destroys the configuration it is switching away
-- from is a change nobody can back out of. They are simply not rendered.
ALTER TABLE orbit.network
    ADD COLUMN firewall_source text NOT NULL DEFAULT 'role'
        CHECK (firewall_source IN ('role', 'policy'));

-- A network cannot be switched to 'policy' with no policy document.
--
-- IN THE DATABASE, because the consequence is a fleet-wide outage and the
-- failure is silent. Nebula's firewall is default-deny: a host rendered with no
-- rules at all does not "fall back" to anything, it drops every packet. So a
-- switch performed against an empty policy takes down the entire network at
-- once, every host reports a successful apply, and convergence reads 100%.
-- Nothing about that looks wrong from the control plane.
--
-- A handler checks this too, so the operator gets a sentence rather than a
-- constraint name — but an invariant enforced in one handler is enforced in
-- whichever handler someone remembers, and this one has to hold for `orbitd`,
-- for a future import path, and for anyone with psql.
--
-- A trigger rather than a CHECK because the fact lives in another table. The
-- WHEN clause means an UPDATE that does not name firewall_source pays nothing
-- at all — the function is not entered.
--
-- ERRCODE 23514 with an explicit CONSTRAINT name, following the pattern
-- 0006 established: it arrives at store.mapErr as ErrInvalid and reaches the
-- caller as a 400 naming the rule, rather than as a 500 that reads like a bug.
CREATE FUNCTION orbit.refuse_empty_policy_source() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM orbit.network_policy WHERE network_id = NEW.id
    ) THEN
        RAISE EXCEPTION
            'network % has no policy document to switch to', NEW.slug
            USING ERRCODE = '23514',
                  CONSTRAINT = 'network_policy_source_requires_document',
                  HINT = 'nebula''s firewall is default-deny, so switching with no '
                         'document renders an empty rule set on every host in the '
                         'network and drops all traffic; PUT a policy document first';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER network_policy_source_requires_document
    BEFORE UPDATE OF firewall_source ON orbit.network
    FOR EACH ROW WHEN (NEW.firewall_source = 'policy'
                       AND OLD.firewall_source IS DISTINCT FROM 'policy')
    EXECUTE FUNCTION orbit.refuse_empty_policy_source();

-- The same rule on INSERT, which is not the same statement and would otherwise
-- be a hole rather than a corner case: a network created directly in 'policy'
-- mode can never have a document — there are no rows referencing an id that did
-- not exist a moment ago — so it is always a network whose every host drops all
-- traffic from its first boot. Two triggers rather than one because the WHEN
-- clause above reads OLD, which does not exist on an INSERT.
CREATE TRIGGER network_policy_source_requires_document_insert
    BEFORE INSERT ON orbit.network
    FOR EACH ROW WHEN (NEW.firewall_source = 'policy')
    EXECUTE FUNCTION orbit.refuse_empty_policy_source();

--------------------------------------------------------------------------------
-- GRANT
--------------------------------------------------------------------------------
--
-- This migration creates a table, so it carries its own grant. 0002 explains
-- why that is a house rule rather than pedantry: the blanket GRANT ... ON ALL
-- TABLES there was evaluated once and is not a standing rule, and ALTER DEFAULT
-- PRIVILEGES is keyed on the creating role — so a migration applied by a
-- different superuser would leave this table with no grant at all, and the
-- omission would surface at runtime as a permission error on a write path.
GRANT SELECT, INSERT, UPDATE, DELETE ON orbit.network_policy TO orbit_app;

-- UPDATE and DELETE are granted deliberately, and the reasoning is worth
-- recording because the append-only argument does apply here in spirit.
--
-- orbit.audit_log has UPDATE and DELETE revoked (0002) because an audit trail the
-- application can rewrite is not an audit trail. This table is not that: it is
-- operational state whose history is a convenience, not evidence. The audit log
-- is still where "who changed the policy, and when" is answered, and that record
-- remains unrewritable. Revoking DELETE here would also make ON DELETE CASCADE
-- from orbit.network fail, which would leave a deleted network's policy rows
-- behind forever.
--
-- Nothing in the application issues an UPDATE or DELETE against this table
-- today; store/policy.go only inserts.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'network_policy' AND privilege_type = 'INSERT'
    ) THEN
        RAISE EXCEPTION 'orbit_app must hold INSERT on orbit.network_policy';
    END IF;
END
$$;
