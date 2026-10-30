-- Preserve original issued-right proofs; new admissions carry v2 joint authorization.
-- A legacy row can be enriched only by genuine same-binding authorization.
ALTER TABLE expiry_owner_key
	ADD COLUMN proof_version SMALLINT NOT NULL DEFAULT 1 CHECK (proof_version IN (1, 2)),
	ADD COLUMN joint_proof TEXT CHECK (joint_proof IS NULL OR length(joint_proof) = 326),
	ADD CONSTRAINT expiry_owner_key_joint_required CHECK (proof_version = 1 OR joint_proof IS NOT NULL);
