-- A network with an IPv6 prefix must issue version 2 certificates.
--
-- Nebula refuses outright: cert/cert_v1.go's validation rejects any non-CA
-- certificate whose networks contain an IPv6 address —
--
--     "certificate may not contain IPv6 networks"
--
-- — so a v1 network holding an IPv6 CIDR is not a degraded configuration, it is
-- one where issuance fails. And it fails LATE: the network creates fine, the
-- host creates fine, the address allocates fine, enrollment redeems the
-- credential fine, and the first thing that goes wrong is the signature, by
-- which time the enrollment code is spent and the operator is reading a
-- certificate-properties error that names neither the network nor the setting
-- that caused it.
--
-- In the database rather than in a handler for the usual reason: `orbitd
-- bootstrap` creates networks too, so this cannot be a handler test. It also
-- has to hold for the CIDR-editing path, where the mistake is easier to make —
-- adding an IPv6 prefix to a network someone created as v1 a month ago is a
-- one-field request with no hint that the certificate version is involved.
--
-- A CHECK constraint cannot contain a subquery, so the "does any element of
-- this array have family 6" question needs a function. It is IMMUTABLE and
-- PARALLEL SAFE because it is: family() over a constant array is a pure
-- function of that array.
--
-- (cert/cert_v2.go additionally requires an IPv6 unsafe network to be
-- accompanied by an IPv6 address assignment, and likewise for v4. That rule
-- never binds here: Orbit renders no unsafe_networks at all, so there is
-- nothing to accompany. It would become relevant the day unsafe networks are
-- modelled, and this comment is where to start.)

CREATE FUNCTION orbit.cidrs_have_ipv6(cidr[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS
$$ SELECT coalesce(bool_or(family(c::inet) = 6), false) FROM unnest($1) AS c $$;

GRANT EXECUTE ON FUNCTION orbit.cidrs_have_ipv6(cidr[]) TO orbit_app;

ALTER TABLE orbit.network
    ADD CONSTRAINT network_ipv6_requires_cert_v2
        CHECK (cert_version = 2 OR NOT orbit.cidrs_have_ipv6(cidrs));

-- No table is created, so no table GRANT. The function grant above is explicit
-- for the same reason 0002 insists table grants are: default privileges cover
-- the common case, an explicit grant survives a role mismatch.
