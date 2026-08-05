-- Routes: reaching things that cannot run nebula.
--
-- A machine in the mesh forwards packets for a prefix that is not in the
-- overlay — a Raspberry Pi in front of a lab network, a jump box in front of a
-- VPC. Nebula calls these "unsafe routes", and the name is honest: the far side
-- is not authenticated, not encrypted, and not part of the mesh's trust.
--
-- WHY A TABLE RATHER THAN A COLUMN.
--
-- Two gateways offering the SAME prefix is the whole of high availability here:
-- nebula does weighted ECMP across them and falls to a surviving gateway when
-- one stops answering, with no coordination and no failover protocol. That is
-- two rows for one prefix, which an array column on membership could express
-- only by making every reader join the fleet back together.
--
-- It is also a MEMBERSHIP fact, beside is_lighthouse and is_relay rather than on
-- the device. A Pi that fronts a lab subnet on one network fronts nothing on
-- another, and the same machine may be a gateway in one mesh and an ordinary
-- host in the next.
--
-- WHAT MAKES IT REAL.
--
-- The authority is in the CERTIFICATE, not this table. Nebula requires the
-- gateway's certificate to carry the prefix in its unsafe networks, and a CA
-- constrains what its subordinates may claim (internal/ca, containedBy). So a
-- row here is an intent; it becomes reachable only once a certificate signed by
-- a CA that permits it says so. A database an attacker can write does not
-- grant routing authority — that is the one place this design is stronger than
-- every competitor, all of whom keep it in a control-plane row.

CREATE TABLE orbit.route (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Both, and the composite foreign key below is the reason. A route naming a
    -- membership in another network would render into a config that cannot
    -- work, and the failure would arrive as a gateway nothing can reach rather
    -- than as an error. The same shape orbit.role uses, for the same reason.
    network_id    uuid NOT NULL,
    membership_id uuid NOT NULL,

    -- The prefix this gateway offers. `cidr` rather than text so Postgres
    -- rejects 192.168.88.5/24 — host bits set below the prefix length — which
    -- is the typo that renders a route nothing matches.
    prefix cidr NOT NULL,

    -- Share of traffic among gateways offering the SAME prefix. Nebula's
    -- weighted ECMP; higher takes more.
    --
    -- It does NOT order different prefixes against each other. 192.168.88.0/24
    -- and 0.0.0.0/0 on one gateway need no ordering at all: longest-prefix match
    -- is how every routing table on earth resolves them, automatically and
    -- unconfigurably. A weight that appeared to order those would be a knob
    -- that does nothing, which is worse than no knob.
    weight int NOT NULL DEFAULT 1 CHECK (weight > 0),

    -- NAT on the way out, per route rather than per host.
    --
    -- 0.0.0.0/0 usually wants it: the internet cannot route back to an overlay
    -- address. A LAN prefix usually does not: the far side can be told a static
    -- route, and the operator would rather see real source addresses in their
    -- own logs. One machine can legitimately want both, which is why this is
    -- here and not on membership.
    masquerade boolean NOT NULL DEFAULT false,

    -- Whether the route goes into the consumer's system routing table. False
    -- leaves nebula aware of it without touching the host's routes, which is
    -- what a machine wants when something else owns its routing.
    install boolean NOT NULL DEFAULT true,

    -- Per-route MTU override. NULL takes the tun's.
    mtu int CHECK (mtu IS NULL OR mtu BETWEEN 576 AND 9000),

    created_at timestamptz NOT NULL DEFAULT now(),

    FOREIGN KEY (network_id, membership_id)
        REFERENCES orbit.membership (network_id, id) ON DELETE CASCADE,

    -- One gateway offers one prefix once. Two rows differing only in weight
    -- would be a rendering ambiguity with no right answer.
    UNIQUE (membership_id, prefix)
);

-- Every config render asks "what does this network route, and through whom",
-- so that is the index. Ordered by prefix so two control planes rendering the
-- same network produce the same bytes — the config is signed, and a
-- nondeterministic render would change its digest on every poll.
CREATE INDEX route_network_idx ON orbit.route (network_id, prefix);

-- And the reverse, for showing a membership its own routes and for cascading.
CREATE INDEX route_membership_idx ON orbit.route (membership_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON orbit.route TO orbit_app;

--------------------------------------------------------------------------------
-- The CA's authority to permit any of this
--------------------------------------------------------------------------------
--
-- Recorded so the API can show and check it without parsing a certificate on
-- every request. The certificate remains the authority; this is a readable copy
-- of what was signed into it, exactly as orbit.ca.curve is.
--
-- Empty means the CA permits NO routes, which is what every CA created before
-- this migration was signed with — and it is deliberately not defaulted to
-- anything wider. Widening requires a new CA, because the constraint is signed
-- and a signature cannot be edited. That is a rotation, which Orbit rehearses
-- (design.md 6): the new bundle reaches every host before the new CA signs
-- anything, and a machine that falls behind pulls its configuration and
-- recovers on its own.
ALTER TABLE orbit.ca
    ADD COLUMN unsafe_networks text[] NOT NULL DEFAULT '{}';
