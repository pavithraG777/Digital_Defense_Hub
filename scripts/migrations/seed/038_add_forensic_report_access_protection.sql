BEGIN;

-- The password is stored only as a bcrypt hash. It is never returned by the
-- API and never embedded in report metadata or audit-visible payloads.
ALTER TABLE media_forensic_reports
    ADD COLUMN IF NOT EXISTS access_password_hash TEXT,
    ADD COLUMN IF NOT EXISTS access_password_set_at TIMESTAMPTZ;

COMMIT;
