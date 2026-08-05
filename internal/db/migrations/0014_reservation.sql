-- Reservations: a credential that describes a membership that does not exist
-- yet.
--
-- WHAT CHANGES, AND WHY IT HAS TO.
--
-- Until now an enrollment code was bound to a host an admin had already created
-- through POST /v1/hosts. Under the device model a membership exists BECAUSE a
-- device joined (docs/model.md §5, invariant 1), so pre-creating one is creating
-- a row that names no machine — exactly the thing device_id NOT NULL is meant to
-- forbid, and the reason step 4 cannot land while that endpoint exists.
--
-- The capability it provided is real and does not go away: unattended
-- provisioning needs a machine to come up with its name, address and role
-- already decided, without a human watching a queue. So the intent moves off the
-- host row and onto the credential. An operator reserves a place; the first
-- device to present the code takes it, and the membership is created — with its
-- device — at that moment.
--
-- The two shapes of credential this leaves:
--
--   host_id set          a code for an EXISTING membership. Re-enrolling a
--                        machine that is already on the network.
--   reserved_name set    a RESERVATION. The membership is created on redemption.
--
-- Exactly one, enforced below. A credential that is both would have two answers
-- to "which membership does this produce", and a credential that is neither is
-- a code that redeems into nothing.

ALTER TABLE orbit.enrollment_credential
    -- Nullable again. It was made NOT NULL in 0003 because at that time every
    -- credential named a host and a NULL meant "the control plane would have to
    -- invent one" — which was correct then and is the wrong constraint now that
    -- a reservation legitimately names no host yet.
    ALTER COLUMN host_id DROP NOT NULL,

    -- What the membership will be called. Also the discriminator: its presence
    -- is what makes this row a reservation.
    ADD COLUMN reserved_name text
        CHECK (reserved_name IS NULL OR
               (length(reserved_name) BETWEEN 1 AND 253)),

    -- An optional specific overlay address. NULL allocates from the network's
    -- prefixes on redemption, which is what almost every caller wants; naming
    -- one is for the machines whose address is written into something else —
    -- a lighthouse in a static_host_map, a DNS record, a firewall rule
    -- somewhere Orbit does not manage.
    ADD COLUMN reserved_addr inet,

    ADD COLUMN reserved_role_id uuid,

    -- The role must belong to the same network as the credential. The composite
    -- reference is the same shape orbit.host uses for exactly this reason: a
    -- reference on role id alone would let a reservation carry another
    -- network's role, and the mistake would only surface as a host with a
    -- firewall it should not have.
    ADD CONSTRAINT enrollment_credential_role_fk
        FOREIGN KEY (network_id, reserved_role_id)
        REFERENCES orbit.role (network_id, id) ON DELETE SET NULL,

    -- Exactly one shape.
    ADD CONSTRAINT enrollment_credential_target_check
        CHECK ((host_id IS NOT NULL) <> (reserved_name IS NOT NULL)),

    -- Reserved attributes belong only to a reservation. Without this a code for
    -- an existing host could carry a reserved_addr that nothing would ever read
    -- — a field that looks like it does something and does not.
    ADD CONSTRAINT enrollment_credential_reserved_check
        CHECK (reserved_name IS NOT NULL
               OR (reserved_addr IS NULL AND reserved_role_id IS NULL));

-- A reserved NAME is held against the network for as long as the credential is
-- live, so two reservations cannot promise the same name and the second machine
-- to arrive cannot fail on a constraint an operator never saw.
--
-- Partial on unspent, unexpired rows only: a name freed by a spent code is
-- available again, which is what makes re-reserving after a failed provision
-- work without an operator hunting for the old row.
--
-- It deliberately does NOT cover orbit.host.name. Two unique constraints in two
-- tables cannot be checked as one, so a reservation for a name a host already
-- holds is caught at redemption instead — which is where it has to be caught
-- anyway, because a host can be created under that name after the reservation
-- is made.
CREATE UNIQUE INDEX enrollment_credential_reserved_name_idx
    ON orbit.enrollment_credential (network_id, reserved_name)
    WHERE reserved_name IS NOT NULL AND used_at IS NULL;
