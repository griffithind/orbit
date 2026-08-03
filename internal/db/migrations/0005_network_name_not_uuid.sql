-- A network name may not look like a uuid.
--
-- Network names are globally unique (unlike host and role names, which are
-- unique only within a network), so a name is a legitimate way to address one:
-- GET /v1/networks/prod resolves as well as GET /v1/networks/{uuid}, and that
-- removes a full listing from every CLI command that names a network.
--
-- That only works while the two cannot be confused. A network named
-- "06a3e184-ea0c-405b-9b1c-8434624b36b0" would parse as an id, be looked up as
-- one, and not be found — or worse, find a different network that genuinely has
-- that id. Whichever branch the resolver tries first is wrong for somebody.
--
-- Rejecting the overlap is much simpler than disambiguating it, and it costs
-- nothing anyone wants: a network named after a uuid is unreadable in every
-- context it appears, including the audit log and the CLI's own output.
--
-- In the database rather than in Go because two paths create networks —
-- POST /v1/networks and `orbitd bootstrap` — and an invariant enforced in one
-- handler is enforced in whichever handler someone remembers.

ALTER TABLE orbit.network
    ADD CONSTRAINT network_name_is_not_a_uuid
    CHECK (name !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
