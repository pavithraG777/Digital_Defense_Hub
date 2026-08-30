ALTER TABLE ml_training_jobs
    ADD COLUMN IF NOT EXISTS test_record_count BIGINT NOT NULL DEFAULT 0
    CHECK (test_record_count >= 0);
