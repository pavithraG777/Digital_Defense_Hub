BEGIN;

-- The Python trainer writes its artifact to a shared, mounted path. These
-- fields preserve the engine-reported location and the independently verified
-- SHA-256 digest before any approval can create or activate a model version.
ALTER TABLE ml_training_jobs
    ADD COLUMN IF NOT EXISTS artifact_path TEXT,
    ADD COLUMN IF NOT EXISTS artifact_sha256 VARCHAR(64),
    ADD COLUMN IF NOT EXISTS artifact_format VARCHAR(20),
    ADD COLUMN IF NOT EXISTS processing_duration_ms BIGINT;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ml_training_artifact_hash') THEN
        ALTER TABLE ml_training_jobs ADD CONSTRAINT chk_ml_training_artifact_hash CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[A-Fa-f0-9]{64}$');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ml_training_artifact_format') THEN
        ALTER TABLE ml_training_jobs ADD CONSTRAINT chk_ml_training_artifact_format CHECK (artifact_format IS NULL OR artifact_format IN ('PTH', 'PT', 'ONNX'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ml_training_jobs_approval
    ON ml_training_jobs (organization_id, status, completed_at DESC)
    WHERE status = 'AWAITING_APPROVAL';

COMMIT;
