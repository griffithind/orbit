-- A reservation can say what the machine will BE, not only what it will be called.
--
-- WHAT WAS WRONG.
--
-- A reservation carried a name, an address and a role. It could not say "this
-- machine is a lighthouse", so provisioning one unattended was two operations
-- with a gap between them:
--
--   1. reserve a name, hand the code to cloud-init
--   2. wait for the machine to appear, then PATCH the membership
--
-- and until step 2 landed the machine was in the network doing nothing useful,
-- while every other machine had already been told there is no lighthouse. The
-- one topology that most wants to be provisioned unattended — a fixed-address
-- box in a datacentre, brought up by a template nobody watches — was the one
-- that needed a human at the end.
--
-- It is worse than an inconvenience. A reservation exists precisely because the
-- machine has not arrived; requiring a follow-up call means the operator's
-- intent is recorded in two places, and the window between them is a window in
-- which the intent is half-applied.
--
-- WHAT THIS ADDS.
--
-- The rest of the intent, on the same row that already holds the name:
--
--   reserved_is_lighthouse   \  membership facts, applied when the code is
--   reserved_is_relay         > redeemed and the membership comes into
--   reserved_advertise_port  /  existence
--
--   reserved_public_addrs       a DEVICE fact, seeded onto the machine
--
-- The last one is the interesting one, and the reason this migration is worth
-- having rather than a PATCH being fine. A lighthouse's public address is known
-- BEFORE the machine exists — that is what makes it a lighthouse. The operator
-- already types it into their cloud provider. Recording it on the reservation
-- means the address is stated once, at the moment it is decided, instead of
-- being carried in someone's head until the machine phones home.

ALTER TABLE orbit.enrollment_credential
    -- NOT NULL DEFAULT false rather than nullable: "the reservation did not say"
    -- and "the reservation said no" are the same thing here. A three-valued
    -- topology flag would force a nil branch at redemption for a distinction
    -- with no consequence.
    ADD COLUMN reserved_is_lighthouse boolean NOT NULL DEFAULT false,
    ADD COLUMN reserved_is_relay      boolean NOT NULL DEFAULT false,

    -- Hosts only, no ports — the same shape as device.public_addrs, which is
    -- where these land. See migration 0019 for why the port is not in here.
    ADD COLUMN reserved_public_addrs text[] NOT NULL DEFAULT '{}',

    -- For the machine behind port forwarding, where the port that reaches it is
    -- deliberately not the port it binds. Nullable because unset is the answer
    -- for almost everything, and here NULL genuinely means "derive it".
    ADD COLUMN reserved_advertise_port int
        CHECK (reserved_advertise_port IS NULL
               OR reserved_advertise_port BETWEEN 1 AND 65535);

-- The same rule 0014 applied to reserved_addr and reserved_role_id: a credential
-- for an EXISTING membership (re-enrolment) must not carry reservation fields,
-- because nothing would ever read them and a reader would reasonably believe
-- they took effect.
--
-- 0014's constraint is replaced rather than added to, so there is one statement
-- of the rule instead of two that can drift apart.
ALTER TABLE orbit.enrollment_credential
    DROP CONSTRAINT enrollment_credential_reserved_check;

ALTER TABLE orbit.enrollment_credential
    ADD CONSTRAINT enrollment_credential_reserved_check
        CHECK (reserved_name IS NOT NULL
               OR (reserved_addr IS NULL
                   AND reserved_role_id IS NULL
                   AND reserved_is_lighthouse = false
                   AND reserved_is_relay = false
                   AND reserved_advertise_port IS NULL
                   AND cardinality(reserved_public_addrs) = 0));

-- A relay is not a lighthouse and neither implies the other, so there is no
-- constraint between them. But a lighthouse with nowhere to be reached is the
-- one combination that is always wrong, and it fails SILENTLY: the membership is
-- created, marked am_lighthouse, and every other machine is told to dial an
-- empty list.
--
-- Not a CHECK, deliberately. The addresses may already be on the DEVICE from a
-- network it joined earlier — one machine, one set of public addresses — and a
-- constraint here cannot see that. enroll.Reserve refuses the combination it CAN
-- see (a lighthouse reservation for a name nothing else knows, with no
-- addresses), which is where the operator is standing and where the error can
-- name both fixes.
