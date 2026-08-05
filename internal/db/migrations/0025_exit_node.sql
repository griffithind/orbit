-- Exit nodes: a default route, which nobody should acquire by accident.
--
-- An exit node IS a route, for 0.0.0.0/0. Everything built for routes already
-- carries it: the table, the certificate authority, the render, the policy. So
-- this migration adds one thing, and it is the thing that makes the difference.
--
-- WHY OPT-IN, WHEN ORDINARY ROUTES ARE NOT.
--
-- A route to 192.168.88.0/24 reaches a consumer through policy, and the
-- operator who wrote that policy already decided. 0.0.0.0/0 is different in
-- kind rather than degree: it captures EVERYTHING. Rendering it to every
-- machine in a network the moment somebody adds the route would silently move a
-- whole fleet's internet traffic through one Raspberry Pi — a change nobody
-- asked for, visible only as a latency complaint.
--
-- So a member takes an exit node deliberately, and takes ONE. Two default
-- routes is a tie broken by whichever weight happens to be larger, which is not
-- a decision anybody made.
--
-- WHAT THIS IS NOT. It is not access control: policy still decides whether this
-- membership may reach 0.0.0.0/0 through that gateway at all, and choosing a
-- gateway policy forbids produces a route that carries nothing. Opt-in answers
-- "which of the permitted ones", not "am I permitted".

ALTER TABLE orbit.membership
    -- The route this membership uses as its default. NULL — the overwhelming
    -- majority — means ordinary internet access over whatever local network
    -- the machine is on.
    --
    -- References the ROUTE rather than the gateway membership, because a
    -- gateway may offer several prefixes and only one of them is the default.
    -- Pointing at the membership would leave "which of its routes did you
    -- mean" to be inferred, and the answer would be wrong the day a gateway
    -- offers both 0.0.0.0/0 and a LAN.
    --
    -- ON DELETE SET NULL: withdrawing an exit node's route returns everyone
    -- using it to their local internet. That is the correct failure — the
    -- alternative, refusing to delete a route while somebody uses it, means an
    -- operator cannot revoke a gateway they have decided to stop trusting.
    ADD COLUMN exit_route_id uuid REFERENCES orbit.route (id) ON DELETE SET NULL;

CREATE INDEX membership_exit_route_idx ON orbit.membership (exit_route_id)
    WHERE exit_route_id IS NOT NULL;
