-- P-256, and the database is what says so.
--
-- WHY THE CHOICE IS GONE.
--
-- A network's curve is PERMANENT. Nebula refuses a certificate whose curve
-- differs from its signer's (cert/ca_pool.go) and nothing updates
-- orbit.network.curve, so the wrong answer means building a new network and
-- re-enrolling every machine. There is no migration, only a rebuild.
--
-- There is also only one defensible answer. P-256 is the only curve on which a
-- host key can live in hardware: TPM 2.0 has no Curve25519 at all, Apple's
-- Secure Enclave is P-256 only, Windows' Platform Crypto Provider is ECDSA
-- P-256/P-384, and nebula's own PKCS#11 support exists only for P-256
-- (noiseutil.DHP256PKCS11, with no 25519 equivalent). A CURVE25519 network can
-- never have a hardware-backed host key, forever.
--
-- WHAT IT COSTS: nothing that reaches the data plane. The curve selects only the
-- Noise handshake's DH function — pki.go newCipherSuite — while the AEAD and
-- hash come from the separate `cipher` setting, so every packet after the
-- handshake is byte-for-byte the same work either way. Measured, P-256 costs
-- about 10% on the handshake DH and 24% on a certificate verify: on the order of
-- 10-20 microseconds, once per peer pair.
--
-- WHY A CONSTRAINT AND NOT JUST A CONSTANT.
--
-- Because the constants already disagreed. `orbitd bootstrap` defaulted to P256
-- while every `orbit agent` path defaulted to CURVE25519, so a machine following
-- the documented steps failed its claim with a curve mismatch. Neither default
-- was wrong on its own, which is exactly why it survived — two constants in two
-- binaries have no way to notice they differ.
--
-- One place that refuses the wrong value does. A future release that reintroduces
-- a -curve flag fails here, on the insert, instead of at a machine's first
-- handshake weeks later.

-- Existing rows first. Migration 0017 truncated orbit.network CASCADE when it
-- introduced network identity keys, so in practice there are none — but a
-- constraint added over data it has not checked is a constraint that fails on a
-- deployment nobody tested, at 3am, mid-upgrade.
DO $$
DECLARE
    stale int;
BEGIN
    SELECT count(*) INTO stale FROM orbit.network WHERE curve <> 'P256';
    IF stale > 0 THEN
        RAISE EXCEPTION
            'this deployment has % CURVE25519 network(s), and Orbit is now '
            'P-256 only. A network''s curve cannot be changed — nebula refuses '
            'a certificate whose curve differs from its signer''s — so the way '
            'forward is a new network and a re-join of every machine. '
            'Delete the old networks and re-run this migration.', stale;
    END IF;
END
$$;

ALTER TABLE orbit.network
    ADD CONSTRAINT network_curve_p256 CHECK (curve = 'P256');

-- The CA's curve must match its network's, which the application already
-- guarantees by construction. Stated here for the same reason: a constraint
-- catches a future code path that forgets.
ALTER TABLE orbit.ca
    ADD CONSTRAINT ca_curve_p256 CHECK (curve = 'P256');

-- The DEFAULT is the trap, not the CHECK.
--
-- 0001 wrote `DEFAULT 'CURVE25519'`, so an INSERT that omits the column would
-- now violate the constraint above and fail — correctly, but with a message
-- about a check rather than about a default nobody remembered. Move it.
ALTER TABLE orbit.network ALTER COLUMN curve SET DEFAULT 'P256';
