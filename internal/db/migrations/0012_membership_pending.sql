-- The `pending` membership state: joined, not yet authorized.
--
-- A device that joins without presenting an enrollment code lands here. The row
-- exists — so an operator can see the machine asking, and decide — and it holds
-- nothing: no overlay address, no certificate, no reach. Authorization is what
-- allocates those.
--
-- WHY A STATE RATHER THAN A SEPARATE TABLE.
--
-- A join request and a membership are the same row at two moments in its life,
-- not two kinds of thing. Splitting them would mean writing every read twice
-- ("is it here, or is it over there?"), and it would put the authorization step
-- in the business of copying columns between tables — the moment where fields
-- silently fail to get carried across.
--
-- Every existing state stays. This migration is purely additive: nothing today
-- produces a `pending` row, and the pre-create-then-enroll path is untouched.
-- See docs/model.md §6, step 1.

ALTER TABLE orbit.host
    DROP CONSTRAINT host_state_check;

ALTER TABLE orbit.host
    ADD CONSTRAINT host_state_check
    CHECK (state IN ('pending', 'created', 'enrolled', 'active', 'suspended', 'deleted'));

-- Listing what is waiting for a human is the query this state exists to serve,
-- and it is the one an operator runs repeatedly while provisioning. The
-- existing (network_id, state) index covers it, so this adds only the partial
-- index that keeps the pending set cheap to scan as the fleet grows and the
-- pending set stays small.
CREATE INDEX host_pending_idx ON orbit.host (network_id, created_at)
    WHERE state = 'pending';
