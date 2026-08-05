-- A machine's public addresses belong to the machine.
--
-- WHAT WAS WRONG.
--
-- orbit.membership.static_addrs held `host:port` entries — the underlay
-- addresses other machines dial to reach a lighthouse or relay. That single
-- string welded two facts from two different nouns:
--
--   the HOST is the machine's public address        -> a device fact
--   the PORT is which nebula instance answers there -> a membership fact
--
-- The port has to be per-membership: two networks on one machine run two nebula
-- processes and cannot share a UDP port (see the comment on
-- orbit.membership.listen_port). But the ADDRESS is one machine's address, and
-- storing it per membership means a machine that is a lighthouse on two networks
-- holds its public IP twice, differing only after the colon.
--
-- The consequence was concrete and already painful: changing a machine's public
-- address meant editing every membership it holds, and getting one wrong left a
-- lighthouse advertising somewhere nothing is listening — which every other
-- machine then dials forever.
--
-- WHAT REPLACES IT.
--
--   device.public_addrs        the addresses, once per machine
--   membership.advertise_port  the port, when it differs from listen_port
--
-- and static_addrs is DERIVED at render time as the cross product. A changed
-- public address is now one write that fixes every network the machine is a
-- lighthouse for.

ALTER TABLE orbit.device
    -- Hosts only — no ports. A name is allowed as well as an address, because
    -- a lighthouse behind dynamic DNS is a real deployment and nebula resolves
    -- static_host_map entries.
    --
    -- Empty for almost every machine. Only a lighthouse or a relay needs to be
    -- dialable at a known address; everything else is found by punching.
    ADD COLUMN public_addrs text[] NOT NULL DEFAULT '{}';

ALTER TABLE orbit.membership
    -- The port other machines dial, when it is NOT the port nebula binds.
    --
    -- NULL means "use listen_port", which is the common case. This exists for
    -- the deployment that forwards an external port to a different internal one
    -- — without it, a machine behind port-forwarding advertises the port it
    -- binds rather than the port that reaches it, and nothing can connect.
    ADD COLUMN advertise_port int CHECK (advertise_port IS NULL OR advertise_port BETWEEN 1 AND 65535);

-- Carry existing lighthouses across rather than losing them.
--
-- Every distinct host part of every static_addrs entry becomes a public address
-- on that membership's device. The port is dropped: it is recoverable from
-- listen_port, and where it is not, the operator sets advertise_port — which is
-- a smaller and more visible fix than a lighthouse that silently stops being
-- reachable.
--
-- split_part on the LAST colon would be wrong for bare IPv6, and right for the
-- `[::1]:4242` form nebula actually accepts. Existing entries are v4 in
-- practice; anything that does not split cleanly is carried over whole, which
-- fails loudly at render rather than quietly producing a wrong address.
UPDATE orbit.device d
   SET public_addrs = sub.addrs
  FROM (
      SELECT m.device_id,
             array_agg(DISTINCT
                 CASE WHEN a ~ '^\[.*\]:[0-9]+$' THEN substring(a from '^\[(.*)\]:[0-9]+$')
                      WHEN a ~ '^[^:]+:[0-9]+$'  THEN split_part(a, ':', 1)
                      ELSE a END) AS addrs
        FROM orbit.membership m, unnest(m.static_addrs) AS a
       WHERE array_length(m.static_addrs, 1) > 0
       GROUP BY m.device_id
  ) AS sub
 WHERE d.id = sub.device_id;

ALTER TABLE orbit.membership DROP COLUMN static_addrs;

-- Finding the lighthouses of a network is the query every config render makes,
-- and it now crosses from membership to device. The device join is already
-- indexed (membership_device_id_idx); this covers the other half.
CREATE INDEX device_public_addrs_idx ON orbit.device (id)
    WHERE array_length(public_addrs, 1) > 0;
