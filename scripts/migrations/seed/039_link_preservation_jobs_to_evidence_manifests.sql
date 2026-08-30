BEGIN;

ALTER TABLE evidence_preservation_jobs
    ADD COLUMN IF NOT EXISTS manifest_evidence_id UUID;

CREATE INDEX IF NOT EXISTS idx_evidence_preservation_jobs_manifest
    ON evidence_preservation_jobs (organization_id, manifest_evidence_id)
    WHERE manifest_evidence_id IS NOT NULL;

COMMIT;
