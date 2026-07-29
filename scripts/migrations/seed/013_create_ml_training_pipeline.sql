BEGIN;

-- Datasets are organization-owned metadata records. Training files remain in
-- the protected storage service; their immutable SHA-256 digest is retained
-- here to make every later model version reproducible.
CREATE TABLE IF NOT EXISTS ml_training_datasets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    dataset_code VARCHAR(100) NOT NULL,
    dataset_name VARCHAR(255) NOT NULL,
    description TEXT,
    media_type VARCHAR(30) NOT NULL,
    storage_uri TEXT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    record_count BIGINT NOT NULL DEFAULT 0,
    label_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(30) NOT NULL DEFAULT 'REGISTERED',
    registered_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    registered_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_ml_training_dataset_code UNIQUE (organization_id, dataset_code),
    CONSTRAINT uq_ml_training_dataset_hash UNIQUE (organization_id, sha256_hash),
    CONSTRAINT chk_ml_training_dataset_media_type CHECK (media_type IN ('IMAGE', 'VIDEO', 'AUDIO', 'DOCUMENT', 'MULTIMODAL')),
    CONSTRAINT chk_ml_training_dataset_status CHECK (status IN ('REGISTERED', 'VALIDATING', 'READY', 'REJECTED', 'ARCHIVED')),
    CONSTRAINT chk_ml_training_dataset_record_count CHECK (record_count >= 0),
    CONSTRAINT chk_ml_training_dataset_hash CHECK (sha256_hash ~ '^[A-Fa-f0-9]{64}$')
);

-- A version pins a dataset definition even when the parent dataset receives a
-- later upload or correction.
CREATE TABLE IF NOT EXISTS ml_training_dataset_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dataset_id UUID NOT NULL REFERENCES ml_training_datasets(id) ON DELETE CASCADE,
    version_number VARCHAR(80) NOT NULL,
    storage_uri TEXT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    record_count BIGINT NOT NULL DEFAULT 0,
    class_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    validation_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(30) NOT NULL DEFAULT 'DRAFT',
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    validated_at TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_ml_training_dataset_version UNIQUE (dataset_id, version_number),
    CONSTRAINT chk_ml_training_dataset_version_status CHECK (status IN ('DRAFT', 'VALIDATING', 'READY', 'REJECTED', 'ARCHIVED')),
    CONSTRAINT chk_ml_training_dataset_version_record_count CHECK (record_count >= 0),
    CONSTRAINT chk_ml_training_dataset_version_hash CHECK (sha256_hash ~ '^[A-Fa-f0-9]{64}$')
);

CREATE TABLE IF NOT EXISTS ml_training_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    dataset_version_id UUID NOT NULL REFERENCES ml_training_dataset_versions(id) ON DELETE RESTRICT,
    ai_model_id UUID REFERENCES ai_models(id) ON DELETE SET NULL,
    job_number VARCHAR(100) NOT NULL,
    job_type VARCHAR(40) NOT NULL DEFAULT 'DEEPFAKE_TRAINING',
    status VARCHAR(30) NOT NULL DEFAULT 'QUEUED',
    split_configuration JSONB NOT NULL,
    training_configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    execution_configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    train_record_count BIGINT,
    validation_record_count BIGINT,
    test_record_count BIGINT,
    requested_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    worker_node VARCHAR(255),
    error_code VARCHAR(100),
    error_message TEXT,
    started_at TIMESTAMP WITHOUT TIME ZONE,
    completed_at TIMESTAMP WITHOUT TIME ZONE,
    cancelled_at TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_ml_training_job_number UNIQUE (organization_id, job_number),
    CONSTRAINT chk_ml_training_job_type CHECK (job_type IN ('DEEPFAKE_TRAINING', 'FINE_TUNING', 'VALIDATION')),
    CONSTRAINT chk_ml_training_job_status CHECK (status IN ('QUEUED', 'PREPARING', 'RUNNING', 'VALIDATING', 'AWAITING_APPROVAL', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT chk_ml_training_job_counts CHECK ((train_record_count IS NULL OR train_record_count >= 0) AND (validation_record_count IS NULL OR validation_record_count >= 0) AND (test_record_count IS NULL OR test_record_count >= 0))
);

CREATE TABLE IF NOT EXISTS ml_training_job_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    training_job_id UUID NOT NULL REFERENCES ml_training_jobs(id) ON DELETE CASCADE,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC(14, 8) NOT NULL,
    dataset_split VARCHAR(20) NOT NULL DEFAULT 'VALIDATION',
    epoch_number INTEGER,
    recorded_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_ml_training_metric_split CHECK (dataset_split IN ('TRAIN', 'VALIDATION', 'TEST')),
    CONSTRAINT chk_ml_training_metric_epoch CHECK (epoch_number IS NULL OR epoch_number >= 0)
);

-- A training output may be approved once, and records the eventual model
-- version and activation decision without allowing an approval to be silently
-- rewritten.
CREATE TABLE IF NOT EXISTS ml_training_model_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    training_job_id UUID NOT NULL UNIQUE REFERENCES ml_training_jobs(id) ON DELETE CASCADE,
    ai_model_version_id UUID UNIQUE REFERENCES ai_model_versions(id) ON DELETE SET NULL,
    decision VARCHAR(20) NOT NULL,
    decision_reason TEXT,
    decided_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    decided_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_at TIMESTAMP WITHOUT TIME ZONE,
    activation_reason TEXT,

    CONSTRAINT chk_ml_training_model_approval_decision CHECK (decision IN ('APPROVED', 'REJECTED'))
);

CREATE INDEX IF NOT EXISTS idx_ml_training_datasets_organization ON ml_training_datasets (organization_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_training_dataset_versions_dataset ON ml_training_dataset_versions (dataset_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_training_jobs_organization ON ml_training_jobs (organization_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_training_job_metrics_job ON ml_training_job_metrics (training_job_id, recorded_at);

COMMIT;
