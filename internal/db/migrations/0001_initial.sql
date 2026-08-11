-- The Orbit schema.
--
-- This is the whole schema in one file. It replaces the twenty-six sequential
-- migrations that built it, which is safe to do exactly once and only before
-- anyone is running the thing: ADR-0005, no compatibility before v1.
--
-- What was kept from those files and what was not. A migration explains two
-- different things at once — why the schema looks like this, and why it stopped
-- looking like it used to. The first belongs here and was carried across. The
-- second is archaeology about renames and drops that no longer exist to be
-- explained, and it stays in git history where it can be read in order.
--
-- The house rule for everything after this file: A MIGRATION THAT CREATES A
-- TABLE MUST STILL CARRY ITS OWN EXPLICIT GRANT. The reason is at the bottom.

CREATE SCHEMA IF NOT EXISTS orbit;

------------------------------------------------------------------------------
-- Helpers used by constraints below.
------------------------------------------------------------------------------

CREATE FUNCTION orbit.cidrs_have_ipv6(cidr[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$ SELECT coalesce(bool_or(family(c::inet) = 6), false) FROM unnest($1) AS c $_$;

------------------------------------------------------------------------------
-- The deployment itself
-- One deployment manages the networks of one organization. These three tables are
-- about the deployment rather than about any network in it: which control-plane
-- processes are alive, and the keys under which everything else's secrets are
-- encrypted at rest.
------------------------------------------------------------------------------

CREATE TABLE orbit.control_plane (
    network_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    addr inet NOT NULL,
    agent_port integer NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT control_plane_agent_port_check CHECK (((agent_port > 0) AND (agent_port < 65536)))
);

ALTER TABLE ONLY orbit.control_plane
    ADD CONSTRAINT control_plane_pkey PRIMARY KEY (network_id, addr);

CREATE INDEX control_plane_liveness_idx ON orbit.control_plane USING btree (network_id, last_seen_at DESC);

CREATE TABLE orbit.kek (
    id boolean DEFAULT true NOT NULL,
    salt bytea NOT NULL,
    verifier_nonce bytea NOT NULL,
    verifier_ciphertext bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT kek_id_check CHECK (id),
    CONSTRAINT kek_salt_check CHECK ((length(salt) = 16))
);

ALTER TABLE ONLY orbit.kek
    ADD CONSTRAINT kek_pkey PRIMARY KEY (id);

-- secret
--
-- Secrets are encrypted with a key derived from the operator's passphrase, not
-- stored beside the data they protect. kek holds the salt and a verifier so a
-- wrong passphrase fails loudly at startup rather than producing garbage plaintext
-- on first use. Its id is a boolean CHECKed to true, which is how a table is
-- constrained to hold at most one row.

CREATE TABLE orbit.secret (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    network_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT secret_kind_check CHECK ((kind = ANY (ARRAY['ca_signing_key'::text, 'network_identity_key'::text]))),
    CONSTRAINT secret_nonce_check CHECK ((length(nonce) = 24))
);

ALTER TABLE ONLY orbit.secret
    ADD CONSTRAINT secret_pkey PRIMARY KEY (id);

CREATE INDEX secret_network_idx ON orbit.secret USING btree (network_id, kind);

------------------------------------------------------------------------------
-- Networks
-- A network is an overlay: one CA, one address space, one policy document.
------------------------------------------------------------------------------

-- network
--
-- Three columns look similar and are not. id is the immutable primary key and
-- never leaves the database. slug is the name everywhere else — in URLs, in the
-- CLI, and as a directory name on every managed host — which is why a trigger
-- refuses to let it change; renaming it would orphan state on every host in the
-- network. name is a display string and means nothing to a machine.
--
-- network_id is nebula's own network identifier, a 16-character base32 string.
--
-- cert_version is 1 or 2, but IPv6 forces 2: nebula's cert/cert_v1.go rejects a
-- non-CA certificate carrying an IPv6 address outright, so a v1 network with an
-- IPv6 CIDR would issue certificates that no host would accept. The CHECK uses
-- cidrs_have_ipv6 to refuse the combination at write time rather than at issuance.
--
-- curve carries one permitted value and one constraint saying so. It had two —
-- an enum-style check listing CURVE25519 and P256, and a narrower one requiring
-- P256 — where the narrower subsumes the wider, so the wider could never fail.
-- orbit.ca carried the same pair and lost the same one.
-- The column stays because nebula's config names the curve; the dead constraint
-- does not.
--
-- routes_changed_at exists because a route is only an intent until the gateway's
-- CERTIFICATE carries the prefix. It tells the issuer that outstanding
-- certificates no longer describe the topology.

CREATE TABLE orbit.network (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    cidrs cidr[] NOT NULL,
    cert_version smallint DEFAULT 2 NOT NULL,
    curve text DEFAULT 'P256'::text NOT NULL,
    cert_ttl interval DEFAULT '24:00:00'::interval NOT NULL,
    config_epoch bigint DEFAULT 1 NOT NULL,
    blocklist_epoch bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    slug text NOT NULL,
    listen_port integer,
    config_overrides jsonb DEFAULT '{}'::jsonb NOT NULL,
    firewall_source text DEFAULT 'role'::text NOT NULL,
    identity_public_key bytea NOT NULL,
    network_id text NOT NULL,
    identity_signer_ref text NOT NULL,
    CONSTRAINT network_cert_ttl_check CHECK ((cert_ttl > '00:00:00'::interval)),
    CONSTRAINT network_cert_version_check CHECK ((cert_version = ANY (ARRAY[1, 2]))),
    CONSTRAINT network_config_overrides_check CHECK ((jsonb_typeof(config_overrides) = 'object'::text)),
    CONSTRAINT network_curve_p256 CHECK ((curve = 'P256'::text)),
    CONSTRAINT network_firewall_source_check CHECK ((firewall_source = ANY (ARRAY['role'::text, 'policy'::text]))),
    CONSTRAINT network_identity_public_key_check CHECK ((length(identity_public_key) = 32)),
    CONSTRAINT network_ipv6_requires_cert_v2 CHECK (((cert_version = 2) OR (NOT orbit.cidrs_have_ipv6(cidrs)))),
    CONSTRAINT network_listen_port_check CHECK (((listen_port > 0) AND (listen_port < 65536))),
    CONSTRAINT network_name_shape CHECK ((((char_length(name) >= 1) AND (char_length(name) <= 65)) AND (name ~ '^[[:alnum:] ''-]+$'::text) AND (name = btrim(name)))),
    CONSTRAINT network_network_id_check CHECK ((network_id ~ '^[0-9abcdefghjkmnpqrstvwxyz]{16}$'::text)),
    CONSTRAINT network_slug_charset CHECK ((slug ~ '^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$'::text))
);

ALTER TABLE ONLY orbit.network
    ADD CONSTRAINT network_name_key UNIQUE (name);

ALTER TABLE ONLY orbit.network
    ADD CONSTRAINT network_network_id_key UNIQUE (network_id);

ALTER TABLE ONLY orbit.network
    ADD CONSTRAINT network_pkey PRIMARY KEY (id);

ALTER TABLE ONLY orbit.network
    ADD CONSTRAINT network_slug_unique UNIQUE (slug);

CREATE FUNCTION orbit.refuse_empty_policy_source() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

CREATE FUNCTION orbit.refuse_network_slug_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION
        'network slug is immutable: % cannot become %', OLD.slug, NEW.slug
        USING ERRCODE = '23514',
              CONSTRAINT = 'network_slug_immutable',
              HINT = 'the slug is a directory name on every managed host in this '
                     'network; create a new network instead, or edit the display name';
END
$$;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TRIGGER network_policy_source_requires_document BEFORE UPDATE OF firewall_source ON orbit.network FOR EACH ROW WHEN (((new.firewall_source = 'policy'::text) AND (old.firewall_source IS DISTINCT FROM 'policy'::text))) EXECUTE FUNCTION orbit.refuse_empty_policy_source();

CREATE TRIGGER network_policy_source_requires_document_insert BEFORE INSERT ON orbit.network FOR EACH ROW WHEN ((new.firewall_source = 'policy'::text)) EXECUTE FUNCTION orbit.refuse_empty_policy_source();

CREATE TRIGGER network_slug_immutable BEFORE UPDATE OF slug ON orbit.network FOR EACH ROW WHEN ((old.slug IS DISTINCT FROM new.slug)) EXECUTE FUNCTION orbit.refuse_network_slug_change();

-- network_policy
--
-- Orbit expresses firewall policy per role: orbit.role holds firewall_rules and
-- every host carrying that role renders them. What that cannot express is a rule
-- about a set of hosts that is not a role — "the database tier accepts 5432 from
-- the web tier" — and the workaround is a certificate group, which means an edit
-- is a reissuance. A group lives inside the signed certificate, so adding one
-- costs every affected host a certificate lifetime before the change is in force.
--
-- The policy document is the alternative: one document per network, compiled by
-- the control plane into per-host rules by resolving selectors to member
-- ADDRESSES rather than to groups. Addresses are already in the rendered
-- configuration, so an edit is config-only and converges on the next poll.
--
-- It is a table with history rather than a column because "what did the policy say
-- last Tuesday" is a question incidents ask, and about the firewall more than
-- anything else here. The audit log records the ACTION; this table records the
-- DOCUMENT, and they answer different questions.
--
-- network.firewall_source decides which of the two is in force. A trigger refuses
-- to switch a network to 'policy' with no document, because nebula's firewall is
-- default-deny: an empty rule set drops all traffic on every host at once.

CREATE TABLE orbit.network_policy (
    network_id uuid NOT NULL,
    version bigint NOT NULL,
    document jsonb NOT NULL,
    config_epoch bigint NOT NULL,
    author text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT network_policy_config_epoch_check CHECK ((config_epoch > 0)),
    CONSTRAINT network_policy_document_check CHECK ((jsonb_typeof(document) = 'object'::text)),
    CONSTRAINT network_policy_version_check CHECK ((version > 0))
);

ALTER TABLE ONLY orbit.network_policy
    ADD CONSTRAINT network_policy_pkey PRIMARY KEY (network_id, version);

CREATE TABLE orbit.ca (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    network_id uuid NOT NULL,
    name text NOT NULL,
    fingerprint text NOT NULL,
    cert_pem text NOT NULL,
    signer_ref text NOT NULL,
    curve text NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    unsafe_networks text[] DEFAULT '{}'::text[] NOT NULL,
    CONSTRAINT ca_check CHECK ((not_after > not_before)),
    CONSTRAINT ca_curve_p256 CHECK ((curve = 'P256'::text)),
    -- NOT NULL does not mean non-empty, and both of these are worse empty than
    -- absent: a CA row with no certificate is published into every host's trust
    -- bundle as a blank entry, and one with no fingerprint cannot be matched
    -- against the certificates it signed. The API discarded the errors from
    -- marshalling and fingerprinting until 2026-08-11, so this was reachable.
    CONSTRAINT ca_cert_pem_present CHECK ((length(cert_pem) > 0)),
    CONSTRAINT ca_fingerprint_present CHECK ((length(fingerprint) > 0)),
    CONSTRAINT ca_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'active'::text, 'retiring'::text, 'retired'::text])))
);

ALTER TABLE ONLY orbit.ca
    ADD CONSTRAINT ca_network_id_fingerprint_key UNIQUE (network_id, fingerprint);

ALTER TABLE ONLY orbit.ca
    ADD CONSTRAINT ca_network_id_id_key UNIQUE (network_id, id);

ALTER TABLE ONLY orbit.ca
    ADD CONSTRAINT ca_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX ca_one_active_per_network ON orbit.ca USING btree (network_id) WHERE (state = 'active'::text);

------------------------------------------------------------------------------
-- Devices, and their membership of networks
-- A device is a machine. A membership is that machine's place in one network:
-- its address, its certificate, its role. The distinction is the point of the
-- model (docs/model.md 5) — one machine may belong to several networks, and it
-- holds one identity per network, not one identity total.
--
-- A membership therefore cannot exist without a device, and the foreign key at the
-- end of this file is what enforces it.
------------------------------------------------------------------------------

-- device
--
-- A device is the first thing in this schema that is NOT scoped to a network.
--
-- It is a physical machine, identified by a keypair it generated itself at first
-- start — before it had joined anything and before it had heard of a control
-- plane. Nobody issues it, nothing expires it, and it is the same key across every
-- network this machine joins.
--
-- That "nobody issues it" is the point. The agent surface is reachable only over
-- the overlay, so a host would need a working tunnel to renew the certificate that
-- gives it a working tunnel. A second issued credential only moves the problem —
-- two expiring credentials still both expire. An identity that is never issued and
-- never expires cannot fail that way, so a host whose data plane is broken can
-- still report that its data plane is broken. See docs/design-device-identity.md.

CREATE TABLE orbit.device (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_fingerprint text NOT NULL,
    public_key bytea NOT NULL,
    hostname text,
    blocked_at timestamp with time zone,
    blocked_reason text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    os text,
    os_version text,
    kernel text,
    arch text,
    agent_version text,
    nebula_version text,
    disk_encrypted boolean,
    secure_boot boolean,
    firewall_enabled boolean,
    tpm_present boolean,
    facts_observed_at timestamp with time zone,
    posture_observed_at timestamp with time zone,
    public_addrs text[] DEFAULT '{}'::text[] NOT NULL,
    CONSTRAINT device_agent_version_check CHECK (((agent_version IS NULL) OR (length(agent_version) <= 64))),
    CONSTRAINT device_arch_check CHECK (((arch IS NULL) OR (length(arch) <= 32))),
    CONSTRAINT device_blocked_reason_check CHECK (((blocked_reason IS NULL) OR (length(blocked_reason) <= 512))),
    CONSTRAINT device_hostname_check CHECK (((hostname IS NULL) OR (length(hostname) <= 253))),
    CONSTRAINT device_kernel_check CHECK (((kernel IS NULL) OR (length(kernel) <= 128))),
    CONSTRAINT device_nebula_version_check CHECK (((nebula_version IS NULL) OR (length(nebula_version) <= 64))),
    CONSTRAINT device_os_check CHECK (((os IS NULL) OR (length(os) <= 64))),
    CONSTRAINT device_os_version_check CHECK (((os_version IS NULL) OR (length(os_version) <= 128)))
);

ALTER TABLE ONLY orbit.device
    ADD CONSTRAINT device_key_fingerprint_key UNIQUE (key_fingerprint);

ALTER TABLE ONLY orbit.device
    ADD CONSTRAINT device_pkey PRIMARY KEY (id);

CREATE INDEX device_blocked_at_idx ON orbit.device USING btree (blocked_at) WHERE (blocked_at IS NOT NULL);

CREATE INDEX device_posture_gap_idx ON orbit.device USING btree (last_seen_at) WHERE ((disk_encrypted IS NOT TRUE) OR (secure_boot IS NOT TRUE));

CREATE INDEX device_posture_observed_idx ON orbit.device USING btree (posture_observed_at NULLS FIRST);

CREATE INDEX device_public_addrs_idx ON orbit.device USING btree (id) WHERE (array_length(public_addrs, 1) > 0);

-- membership
--
-- A membership is "this device, in that network". That is its definition, not a
-- description of it, which is why device_id is NOT NULL — a row naming no machine
-- is not a partially-filled membership, it is a row that means nothing.
-- docs/model.md 5, invariant 1.
--
-- Three things create one, exhaustively: a device asks (JoinNetwork, pending until
-- authorized), a device redeems a reservation (CreateReservedMembership), or the
-- control plane issues its own (SelfIssue). All three take a device.

CREATE TABLE orbit.membership (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    network_id uuid NOT NULL,
    name text NOT NULL,
    role_id uuid,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    is_lighthouse boolean DEFAULT false NOT NULL,
    is_relay boolean DEFAULT false NOT NULL,
    state text DEFAULT 'created'::text NOT NULL,
    applied_config_epoch bigint DEFAULT 0 NOT NULL,
    applied_blocklist_epoch bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    listen_port integer,
    tun_dev text,
    config_overrides jsonb DEFAULT '{}'::jsonb NOT NULL,
    restart_required_epoch bigint DEFAULT 0 NOT NULL,
    addr_changed_at timestamp with time zone,
    device_id uuid NOT NULL,
    advertise_port integer,
    exit_route_id uuid,
    routes_changed_at timestamp with time zone,
    CONSTRAINT membership_config_overrides_check CHECK ((jsonb_typeof(config_overrides) = 'object'::text)),
    CONSTRAINT membership_listen_port_check CHECK (((listen_port > 0) AND (listen_port < 65536))),
    CONSTRAINT membership_tun_dev_check CHECK ((tun_dev ~ '^[a-z0-9][a-z0-9-]{0,14}$'::text)),
    CONSTRAINT membership_advertise_port_check CHECK (((advertise_port IS NULL) OR ((advertise_port >= 1) AND (advertise_port <= 65535)))),
    CONSTRAINT membership_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'created'::text, 'enrolled'::text, 'active'::text, 'suspended'::text, 'deleted'::text])))
);

ALTER TABLE ONLY orbit.membership
    ADD CONSTRAINT membership_network_id_id_key UNIQUE (network_id, id);

ALTER TABLE ONLY orbit.membership
    ADD CONSTRAINT membership_network_id_name_key UNIQUE (network_id, name);

ALTER TABLE ONLY orbit.membership
    ADD CONSTRAINT membership_pkey PRIMARY KEY (id);

CREATE INDEX membership_convergence_idx ON orbit.membership USING btree (network_id, applied_blocklist_epoch, applied_config_epoch);

CREATE INDEX membership_device_id_idx ON orbit.membership USING btree (device_id);

CREATE INDEX membership_exit_route_idx ON orbit.membership USING btree (exit_route_id) WHERE (exit_route_id IS NOT NULL);

CREATE INDEX membership_network_state_idx ON orbit.membership USING btree (network_id, state);

CREATE INDEX membership_pending_idx ON orbit.membership USING btree (network_id, created_at) WHERE (state = 'pending'::text);

CREATE INDEX membership_role_idx ON orbit.membership USING btree (network_id, role_id);

CREATE TABLE orbit.membership_address (
    network_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    addr inet NOT NULL
);

ALTER TABLE ONLY orbit.membership_address
    ADD CONSTRAINT membership_address_pkey PRIMARY KEY (network_id, addr);

CREATE INDEX membership_address_membership_idx ON orbit.membership_address USING btree (membership_id);

CREATE TABLE orbit.enrollment_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    network_id uuid NOT NULL,
    membership_id uuid,
    method text NOT NULL,
    secret_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    used_from inet,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    reserved_name text,
    reserved_addr inet,
    reserved_role_id uuid,
    reserved_is_lighthouse boolean DEFAULT false NOT NULL,
    reserved_is_relay boolean DEFAULT false NOT NULL,
    reserved_public_addrs text[] DEFAULT '{}'::text[] NOT NULL,
    reserved_advertise_port integer,
    CONSTRAINT enrollment_credential_method_check CHECK ((method = 'code'::text)),
    CONSTRAINT enrollment_credential_reserved_advertise_port_check CHECK (((reserved_advertise_port IS NULL) OR ((reserved_advertise_port >= 1) AND (reserved_advertise_port <= 65535)))),
    CONSTRAINT enrollment_credential_reserved_check CHECK (((reserved_name IS NOT NULL) OR ((reserved_addr IS NULL) AND (reserved_role_id IS NULL) AND (reserved_is_lighthouse = false) AND (reserved_is_relay = false) AND (reserved_advertise_port IS NULL) AND (cardinality(reserved_public_addrs) = 0)))),
    CONSTRAINT enrollment_credential_reserved_name_check CHECK (((reserved_name IS NULL) OR ((length(reserved_name) >= 1) AND (length(reserved_name) <= 253)))),
    CONSTRAINT enrollment_credential_target_check CHECK (((membership_id IS NOT NULL) <> (reserved_name IS NOT NULL)))
);

ALTER TABLE ONLY orbit.enrollment_credential
    ADD CONSTRAINT enrollment_credential_pkey PRIMARY KEY (id);

ALTER TABLE ONLY orbit.enrollment_credential
    ADD CONSTRAINT enrollment_credential_secret_hash_key UNIQUE (secret_hash);

CREATE INDEX enrollment_credential_expiry_idx ON orbit.enrollment_credential USING btree (expires_at) WHERE (used_at IS NULL);

CREATE UNIQUE INDEX enrollment_credential_reserved_name_idx ON orbit.enrollment_credential USING btree (network_id, reserved_name) WHERE ((reserved_name IS NOT NULL) AND (used_at IS NULL));

-- certificate
--
-- Indexed three ways, and every index is partial. A certificate is interesting
-- while it is active and uninteresting forever after, but the rows stay for the
-- audit trail, so an index over the whole table grows without bound while the
-- answers all concern the live slice.

CREATE TABLE orbit.certificate (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    network_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    ca_id uuid NOT NULL,
    fingerprint text NOT NULL,
    pem text NOT NULL,
    cert_version smallint NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT certificate_cert_version_check CHECK ((cert_version = ANY (ARRAY[1, 2]))),
    CONSTRAINT certificate_check CHECK ((not_after > not_before)),
    CONSTRAINT certificate_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'active'::text, 'superseded'::text, 'revoked'::text])))
);

ALTER TABLE ONLY orbit.certificate
    ADD CONSTRAINT certificate_fingerprint_key UNIQUE (fingerprint);

ALTER TABLE ONLY orbit.certificate
    ADD CONSTRAINT certificate_pkey PRIMARY KEY (id);

CREATE INDEX certificate_ca_idx ON orbit.certificate USING btree (ca_id) WHERE (state = 'active'::text);

CREATE INDEX certificate_membership_issued_idx ON orbit.certificate USING btree (membership_id, issued_at DESC, id DESC);

CREATE UNIQUE INDEX certificate_one_active_per_membership_version ON orbit.certificate USING btree (membership_id, cert_version) WHERE (state = 'active'::text);

CREATE INDEX certificate_renewal_idx ON orbit.certificate USING btree (not_after) WHERE (state = 'active'::text);

CREATE TABLE orbit.blocklist_entry (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    network_id uuid NOT NULL,
    fingerprint text NOT NULL,
    reason text,
    epoch bigint NOT NULL,
    not_after timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY orbit.blocklist_entry
    ADD CONSTRAINT blocklist_entry_network_id_fingerprint_key UNIQUE (network_id, fingerprint);

ALTER TABLE ONLY orbit.blocklist_entry
    ADD CONSTRAINT blocklist_entry_pkey PRIMARY KEY (id);

CREATE INDEX blocklist_entry_live_idx ON orbit.blocklist_entry USING btree (network_id, not_after);

------------------------------------------------------------------------------
-- Routes and exit nodes
-- A route is a prefix some member forwards for. An exit node is a route for
-- 0.0.0.0/0 and needs no separate concept.
--
-- A route is only an intent until the gateway's certificate carries the prefix, so
-- the network's routes_changed_at is what tells the issuer that outstanding
-- certificates no longer describe the topology.
------------------------------------------------------------------------------

-- route
--
-- A machine in the mesh forwards packets for a prefix that is not in the overlay.
-- An exit node is the same thing for 0.0.0.0/0 and needs no separate concept.

CREATE TABLE orbit.route (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    network_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    prefix cidr NOT NULL,
    weight integer DEFAULT 1 NOT NULL,
    masquerade boolean DEFAULT false NOT NULL,
    install boolean DEFAULT true NOT NULL,
    mtu integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT route_mtu_check CHECK (((mtu IS NULL) OR ((mtu >= 576) AND (mtu <= 9000)))),
    CONSTRAINT route_weight_check CHECK ((weight > 0))
);

ALTER TABLE ONLY orbit.route
    ADD CONSTRAINT route_membership_id_prefix_key UNIQUE (membership_id, prefix);

ALTER TABLE ONLY orbit.route
    ADD CONSTRAINT route_pkey PRIMARY KEY (id);

CREATE INDEX route_membership_idx ON orbit.route USING btree (membership_id);

CREATE INDEX route_network_idx ON orbit.route USING btree (network_id, prefix);

------------------------------------------------------------------------------
-- Who may act, and how they authenticate
-- Roles group memberships for policy. API tokens and UI sessions are how a human
-- or a script reaches the control plane; neither has anything to do with a host's
-- identity on the overlay, which is a certificate.
------------------------------------------------------------------------------

CREATE TABLE orbit.role (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    network_id uuid NOT NULL,
    name text NOT NULL,
    groups text[] DEFAULT '{}'::text[] NOT NULL,
    firewall_rules jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    groups_changed_at timestamp with time zone
);

ALTER TABLE ONLY orbit.role
    ADD CONSTRAINT role_network_id_id_key UNIQUE (network_id, id);

ALTER TABLE ONLY orbit.role
    ADD CONSTRAINT role_network_id_name_key UNIQUE (network_id, name);

ALTER TABLE ONLY orbit.role
    ADD CONSTRAINT role_pkey PRIMARY KEY (id);

CREATE TABLE orbit.api_token (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    token_hash bytea NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY orbit.api_token
    ADD CONSTRAINT api_token_pkey PRIMARY KEY (id);

ALTER TABLE ONLY orbit.api_token
    ADD CONSTRAINT api_token_token_hash_key UNIQUE (token_hash);

-- ui_session
--
-- A session is a REFERENCE to an API token plus the browser-specific facts a
-- bearer token has no room for: an absolute expiry short enough to survive a
-- stolen laptop, an idle window, and whether the operator asked for a read-only
-- view.
--
-- It is NOT a copy of a credential. There is no scopes column, and that omission
-- is the whole security argument. AuthenticateToken filters on revoked_at and
-- expires_at in the same query that resolves the token, which is what lets
-- RevokeAPIToken claim revocation takes effect on the next request with no
-- propagation delay. A session holding its own copy of the scopes would destroy
-- that silently: revoking the token would leave a live browser session still
-- carrying '*', and nothing would ever look at the token again to notice.
--
-- The consequence is deliberate and tested: deleting a token kills every browser
-- session derived from it, immediately.

CREATE TABLE orbit.ui_session (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_id uuid NOT NULL,
    cookie_hash bytea NOT NULL,
    read_only boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    created_ip inet,
    user_agent text,
    CONSTRAINT ui_session_check CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '12:00:00'::interval)))),
    CONSTRAINT ui_session_user_agent_check CHECK (((user_agent IS NULL) OR (length(user_agent) <= 256)))
);

ALTER TABLE ONLY orbit.ui_session
    ADD CONSTRAINT ui_session_cookie_hash_key UNIQUE (cookie_hash);

ALTER TABLE ONLY orbit.ui_session
    ADD CONSTRAINT ui_session_pkey PRIMARY KEY (id);

CREATE INDEX ui_session_token_id_idx ON orbit.ui_session USING btree (token_id);

------------------------------------------------------------------------------
-- The audit log
-- Append-only, and enforced by a grant rather than by convention — see the end of
-- this file. An audit trail the application can rewrite is not an audit trail.
------------------------------------------------------------------------------

-- audit_log
--
-- Append-only, enforced by the grant at the end of this file rather than by
-- convention. Corrections are new entries.

CREATE TABLE orbit.audit_log (
    id bigint NOT NULL,
    actor_type text NOT NULL,
    actor_id text,
    actor_display text,
    action text NOT NULL,
    target_type text,
    target_id text,
    meta jsonb DEFAULT '{}'::jsonb NOT NULL,
    source_ip inet,
    at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_log_actor_type_check CHECK ((actor_type = ANY (ARRAY['user'::text, 'token'::text, 'agent'::text, 'system'::text])))
);

ALTER TABLE ONLY orbit.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);

ALTER TABLE orbit.audit_log ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME orbit.audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE INDEX audit_log_at_idx ON orbit.audit_log USING btree (at DESC);

------------------------------------------------------------------------------
-- Foreign keys
--
-- Collected here rather than beside their tables so the file can be read top to
-- bottom without forward references, and so the shape of the graph is visible
-- in one place.
------------------------------------------------------------------------------

ALTER TABLE ONLY orbit.blocklist_entry
    ADD CONSTRAINT blocklist_entry_network_id_fkey FOREIGN KEY (network_id) REFERENCES orbit.network(id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.ca
    ADD CONSTRAINT ca_network_id_fkey FOREIGN KEY (network_id) REFERENCES orbit.network(id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.certificate
    ADD CONSTRAINT certificate_network_id_ca_id_fkey FOREIGN KEY (network_id, ca_id) REFERENCES orbit.ca(network_id, id);

ALTER TABLE ONLY orbit.certificate
    ADD CONSTRAINT certificate_network_id_membership_id_fkey FOREIGN KEY (network_id, membership_id) REFERENCES orbit.membership(network_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.control_plane
    ADD CONSTRAINT control_plane_network_id_membership_id_fkey FOREIGN KEY (network_id, membership_id) REFERENCES orbit.membership(network_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.enrollment_credential
    ADD CONSTRAINT enrollment_credential_network_id_membership_id_fkey FOREIGN KEY (network_id, membership_id) REFERENCES orbit.membership(network_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.enrollment_credential
    ADD CONSTRAINT enrollment_credential_role_fk FOREIGN KEY (network_id, reserved_role_id) REFERENCES orbit.role(network_id, id) ON DELETE SET NULL (reserved_role_id);

ALTER TABLE ONLY orbit.membership_address
    ADD CONSTRAINT membership_address_network_id_membership_id_fkey FOREIGN KEY (network_id, membership_id) REFERENCES orbit.membership(network_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.membership
    ADD CONSTRAINT membership_device_id_fkey FOREIGN KEY (device_id) REFERENCES orbit.device(id) ON DELETE RESTRICT;

ALTER TABLE ONLY orbit.membership
    ADD CONSTRAINT membership_network_id_fkey FOREIGN KEY (network_id) REFERENCES orbit.network(id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.membership
    ADD CONSTRAINT membership_network_id_role_id_fkey FOREIGN KEY (network_id, role_id) REFERENCES orbit.role(network_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY orbit.membership
    ADD CONSTRAINT membership_exit_route_id_fkey FOREIGN KEY (exit_route_id) REFERENCES orbit.route(id) ON DELETE SET NULL;

ALTER TABLE ONLY orbit.network_policy
    ADD CONSTRAINT network_policy_network_id_fkey FOREIGN KEY (network_id) REFERENCES orbit.network(id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.role
    ADD CONSTRAINT role_network_id_fkey FOREIGN KEY (network_id) REFERENCES orbit.network(id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.route
    ADD CONSTRAINT route_network_id_membership_id_fkey FOREIGN KEY (network_id, membership_id) REFERENCES orbit.membership(network_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.secret
    ADD CONSTRAINT secret_network_id_fkey FOREIGN KEY (network_id) REFERENCES orbit.network(id) ON DELETE CASCADE;

ALTER TABLE ONLY orbit.ui_session
    ADD CONSTRAINT ui_session_token_id_fkey FOREIGN KEY (token_id) REFERENCES orbit.api_token(id) ON DELETE CASCADE;

------------------------------------------------------------------------------
-- Least privilege for the application role
--
-- Two properties, neither of which is about isolation:
--
--   * The application issues no DDL, so it holds no CREATE.
--   * The audit log is append-only. Not "we don't update it" — the application
--     role has no grant to.
--
-- The application connects as orbit_app rather than as the migration role, so a
-- bug cannot alter the schema and a compromise cannot quietly drop the audit
-- table.
------------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'orbit_app') THEN
        CREATE ROLE orbit_app NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA orbit TO orbit_app;

GRANT ALL ON FUNCTION orbit.cidrs_have_ipv6(cidr[]) TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.api_token TO orbit_app;

GRANT SELECT,INSERT ON TABLE orbit.audit_log TO orbit_app;

GRANT USAGE ON SEQUENCE orbit.audit_log_id_seq TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.blocklist_entry TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.ca TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.certificate TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.control_plane TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.device TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.enrollment_credential TO orbit_app;

GRANT SELECT,INSERT,UPDATE ON TABLE orbit.kek TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.membership TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.membership_address TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.network TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.network_policy TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.role TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.route TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.secret TO orbit_app;

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE orbit.ui_session TO orbit_app;

-- The grants above are evaluated once, right now. They are not a standing rule,
-- so a table created by any later migration would get no grant at all — and that
-- failure surfaces at RUNTIME as a permission error, not at migration time where
-- it would be caught.
--
-- ALTER DEFAULT PRIVILEGES closes that for the common case. It is keyed on
-- (creating role, schema, object type), so it covers objects created by the role
-- running this file. There is no FOR ANY ROLE form: if a later migration is
-- applied by a different superuser, its tables are uncovered again. Hence the
-- house rule at the top of this file.
--
-- Deliberately written without FOR ROLE, which means the role running this
-- migration. pg_dump renders it with the role that happened to apply it baked
-- in, and that form is wrong for anyone who migrates as a different superuser.
ALTER DEFAULT PRIVILEGES IN SCHEMA orbit
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO orbit_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA orbit
    GRANT USAGE ON SEQUENCES TO orbit_app;

-- Assert rather than assume. A grant that silently failed to apply, or a later
-- edit that loosened the audit log, should stop the migration here rather than
-- be discovered when someone needs the trail.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'audit_log' AND privilege_type IN ('UPDATE', 'DELETE')
    ) THEN
        RAISE EXCEPTION 'orbit_app must not hold UPDATE or DELETE on orbit.audit_log';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_privileges
         WHERE grantee = 'orbit_app' AND table_schema = 'orbit'
           AND table_name = 'audit_log' AND privilege_type = 'INSERT'
    ) THEN
        RAISE EXCEPTION 'orbit_app must hold INSERT on orbit.audit_log';
    END IF;
END
$$;
