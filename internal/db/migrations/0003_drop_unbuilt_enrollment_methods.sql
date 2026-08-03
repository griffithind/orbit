-- Remove the enrollment methods that were designed but never built.
--
-- orbit.enrolled_instance and the cloud_iid/attestation values in the method
-- CHECK described a capability the code did not have: there was no handler that
-- could produce a credential with either method, and the only Go function that
-- touched enrolled_instance had no callers. A schema that advertises a method
-- nothing implements misleads anyone reading it for what the system can do.
--
-- Reintroducing either is an ALTER and a handler — the same work as before,
-- minus the misleading scaffolding. TPM attestation additionally forces a
-- curve decision for the whole network, because TPM 2.0 has no X25519.

DROP TABLE IF EXISTS orbit.enrolled_instance;

ALTER TABLE orbit.enrollment_credential
    DROP CONSTRAINT IF EXISTS enrollment_credential_method_check;

ALTER TABLE orbit.enrollment_credential
    ADD CONSTRAINT enrollment_credential_method_check
    CHECK (method IN ('code'));

-- host_id was nullable only so cloud_iid could create the host on redemption.
-- With that path gone every credential names an existing host, and the column
-- should say so: a NULL here now means a bug, not a pending host.
ALTER TABLE orbit.enrollment_credential
    ALTER COLUMN host_id SET NOT NULL;
