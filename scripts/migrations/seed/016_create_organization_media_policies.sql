BEGIN;

CREATE TABLE IF NOT EXISTS organization_media_policies (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    allowed_media_types JSONB NOT NULL DEFAULT '["IMAGE","VIDEO","AUDIO","DOCUMENT"]'::jsonb,
    maximum_upload_bytes BIGINT NOT NULL DEFAULT 52428800,
    review_confidence_threshold NUMERIC(5,2) NOT NULL DEFAULT 75,
    require_review_for_suspicious BOOLEAN NOT NULL DEFAULT true,
    retention_days INTEGER NOT NULL DEFAULT 90,
    updated_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_media_policy_upload_limit CHECK (maximum_upload_bytes > 0),
    CONSTRAINT chk_media_policy_review_threshold CHECK (review_confidence_threshold >= 0 AND review_confidence_threshold <= 100),
    CONSTRAINT chk_media_policy_retention_days CHECK (retention_days >= 1 AND retention_days <= 3650)
);

COMMIT;
