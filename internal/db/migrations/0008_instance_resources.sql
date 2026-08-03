-- Per-instance resources, the config layout, and the restart signal.
--
-- THE PROBLEM THIS SOLVES. One machine may belong to two networks. That is two
-- nebula processes on one kernel, and they need two things that cannot be
-- shared: a UDP listen port, and a tun device name. Until now the listen port
-- was a flag on the control-plane process (enroll.Config.ListenPort), which
-- means every network a replica serves rendered the SAME port into every host's
-- configuration — so the second nebula on a dual-homed machine fails to bind,
-- at start, with an error about a port and nothing about which network wanted
-- it. The tun device was not modelled at all.
--
-- WHERE THE VALUES LIVE, and why both levels.
--
-- The row that represents "this machine, on this network" is orbit.host — it is
-- already scoped to exactly one network — so that is where an instance's
-- resources belong, and a per-host override has to exist because two hosts of
-- the SAME network can legitimately share a machine (every e2e run does this).
--
-- But a per-host value alone is wrong as a default. The collision Orbit can
-- actually reason about is between NETWORKS: it knows a machine's two host rows
-- are in different networks, and it cannot know which host rows are the same
-- machine. So the default belongs on the network, where setting it once makes
-- every host in that network agree, and where two networks differing by one
-- number is the whole fix.
--
-- Hence: NULL on the host means "inherit the network's", and NULL on the
-- network means "use the control plane's configured default". Three levels, one
-- rule, and the zero state is exactly today's behaviour — which is what keeps
-- this migration from silently re-porting a running fleet.
--
-- DELIBERATELY NOT ALLOCATED PER HOST. A distinct port per host would collide
-- with the one thing that has to stay uniform: a lighthouse's static_addrs
-- carry "host:port", every peer dials that literal, and a fleet where each host
-- listens somewhere different is a fleet where hole punching has nothing to
-- assume. Uniform-per-network is the shape nebula is built around.

ALTER TABLE orbit.network
    ADD COLUMN listen_port int
        CHECK (listen_port > 0 AND listen_port < 65536),
    -- Which layout hosts of this network use by default; see the host column.
    ADD COLUMN config_mode text NOT NULL DEFAULT 'authoritative'
        CHECK (config_mode IN ('authoritative', 'fragment')),
    -- Nebula settings Orbit does not model, merged into the rendered
    -- configuration; see the host column for what may and may not be overridden.
    ADD COLUMN config_overrides jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(config_overrides) = 'object');

ALTER TABLE orbit.host
    ADD COLUMN listen_port int
        CHECK (listen_port > 0 AND listen_port < 65536),

    -- tun.dev, and the constraint is doing real work.
    --
    -- Linux copies this into a [16]byte with a bare copy() and no error
    -- (overlay/tun_linux.go), so a name longer than 15 characters is SILENTLY
    -- TRUNCATED — and two names sharing a 15-character prefix become the same
    -- device, which is a collision that reports itself as neither host being
    -- reachable. macOS is the opposite failure: it requires utun[0-9]+, warns
    -- "ignoring" for anything else (overlay/tun_darwin.go), and lets the kernel
    -- pick — so a name Orbit renders may simply not be the device that appears.
    --
    -- 15 characters and interface-legal characters, therefore, enforced where
    -- neither platform will enforce it. The agent overrides this where the
    -- platform forbids the value; that is the agent's job, not the schema's.
    ADD COLUMN tun_dev text
        CHECK (tun_dev ~ '^[a-z0-9][a-z0-9-]{0,14}$'),

    -- 'authoritative': Orbit renders one COMPLETE nebula.yml and nebula is
    -- pointed at that file. 'fragment': Orbit renders config.d/50-orbit.yml into
    -- a directory nebula merges.
    --
    -- The mode is a column rather than something inferred from where a file
    -- happens to sit, because the two modes differ in what Orbit can HONESTLY
    -- SAY. Nebula merges a directory with mergo.WithAppendSlice, so firewall
    -- rules from separate files CONCATENATE: in fragment mode Orbit can neither
    -- see nor remove a rule an operator wrote, and the policy it reports is a
    -- lower bound presented as an answer. In authoritative mode the rendered
    -- file is the whole policy. A reader of the API must be able to tell which
    -- of those two claims they are being handed.
    --
    -- NULL inherits the network's, as with the columns above.
    ADD COLUMN config_mode text
        CHECK (config_mode IN ('authoritative', 'fragment')),

    -- The escape hatch: nebula settings Orbit does not model — tun.mtu, a log
    -- level, an odd punchy delay — merged over the network's own overrides and
    -- over everything Orbit rendered.
    --
    -- It may NOT reach pki.*, firewall.*, static_host_map, the lighthouse and
    -- relay flags, listen.port, or tun.dev. Those are refused rather than
    -- accepted, and the refusal is the point: authoritative mode exists so that
    -- what Orbit reports about a host's policy is the whole truth, and an
    -- override that could rewrite the firewall would reintroduce exactly the
    -- divergence this mode was built to remove — except now the divergence
    -- would look authoritative. listen.port and tun.dev are refused for a
    -- narrower reason: they are already first-class fields, and a second way to
    -- set them is a second source of truth for the value the API reports.
    --
    -- Enforced in nebulacfg at render time as well as at the API, because a
    -- render that silently dropped a protected key would be worse than one that
    -- refuses.
    ADD COLUMN config_overrides jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(config_overrides) = 'object'),

    -- THE RESTART SIGNAL.
    --
    -- Nebula will not accept a certificate whose networks changed on a reload:
    -- pki.go's reloadCert compares the new certificate's Networks against the
    -- running one and refuses the whole reload if they differ ("Networks in new
    -- cert was different from old"). The host installs the new certificate,
    -- nebula DECLINES it, and keeps running the old one until the PROCESS
    -- restarts. Waiting does not fix it; nothing fixes it but a restart.
    --
    -- So an address change has to be able to say "this generation is not a
    -- reload". A monotonic epoch rather than a boolean flag, and the difference
    -- matters:
    --
    --   * A flag has to be cleared by somebody. If the agent clears it, a lost
    --     acknowledgement either leaves it set (restart loop) or clears it early
    --     (the restart never happens). Both are silent.
    --   * An epoch is compared against what the agent has already done, exactly
    --     as applied_config_epoch is. Replaying a report is a no-op, a stale
    --     agent catches up on its own, and nothing has to be cleared — which is
    --     also why it can be reported through the same path convergence already
    --     uses.
    --
    -- Per host, not per network: an address change on one host requires that one
    -- host to restart. Every other host in the network re-renders a
    -- static_host_map, which is an ordinary hot reload.
    --
    -- The value is the config epoch the change produced. The agent restarts once
    -- it has applied a generation at or past this number and has not yet
    -- restarted for it. 0 means no restart has ever been required.
    ADD COLUMN restart_required_epoch bigint NOT NULL DEFAULT 0,

    -- When this host's address set last changed, so its certificate can be
    -- pulled forward instead of waiting out its own half-life.
    --
    -- The addresses are inside the signed certificate, and nebula's firewall
    -- verifies on every packet that a peer's source address appears in its
    -- certificate. A host whose address changed is therefore holding a
    -- certificate that no longer authorises it to send from where it now is —
    -- it is not merely stale, it is unusable — and waiting a median of half a
    -- certificate lifetime for renewal is not a delay, it is downtime.
    --
    -- Same mechanism, and deliberately the same shape, as role.groups_changed_at
    -- (migration 0004): enroll.Service.State compares the active certificate's
    -- issued_at against this and sends RenewAfter = now, which the agent spreads
    -- and clamps. A timestamp rather than an epoch because it is compared
    -- against certificate.issued_at and nothing else.
    ADD COLUMN addr_changed_at timestamptz;

-- No GRANT: no table is created, and a column inherits the privileges of its
-- table.
