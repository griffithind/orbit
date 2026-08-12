-- What the fleet's clocks are doing, so a wrong one is answerable centrally.
--
-- Nebula validates certificate windows against raw wall time with zero leeway,
-- so a machine more than a minute slow rejects its own brand-new certificate:
-- the apply fails, the loop rolls back, and the failure is indistinguishable
-- from a wrong key or a corrupted config. The agent measures the skew on every
-- poll (ADR-0031); this is where it lands so "which machines have bad clocks"
-- has an answer that is not "run netcheck on each of them".
--
-- On the DEVICE rather than the membership: a clock belongs to a machine, and a
-- laptop on three networks has one. Same reasoning as device facts and posture.

ALTER TABLE orbit.device
    ADD COLUMN clock_skew_seconds double precision;

GRANT SELECT, UPDATE ON TABLE orbit.device TO orbit_app;
