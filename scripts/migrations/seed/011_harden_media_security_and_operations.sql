BEGIN;

-- Durable audit trail for quarantine, integrity and
-- non-destructive retention operations.
CREATE TABLE IF NOT EXISTS media_asset_security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    media_asset_id UUID NOT NULL,
    event_type VARCHAR(40) NOT NULL,
    actor_user_id UUID NULL,
    reason TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_media_asset_security_event_type
        CHECK (
            event_type IN (
                'QUARANTINED',
                'RELEASED',
                'INTEGRITY_FAILED',
                'RETENTION_ARCHIVED'
            )
        ),

    CONSTRAINT fk_media_asset_security_event_org
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_media_asset_security_event_asset
        FOREIGN KEY (
            organization_id,
            media_asset_id
        )
        REFERENCES media_analysis_assets (
            organization_id,
            id
        )
        ON DELETE CASCADE,

    CONSTRAINT fk_media_asset_security_event_actor
        FOREIGN KEY (actor_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_media_security_events_asset
    ON media_asset_security_events (
        organization_id,
        media_asset_id,
        created_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_media_security_events_type
    ON media_asset_security_events (
        organization_id,
        event_type,
        created_at DESC
    );

-- Resolve any pre-existing active duplicates before
-- enforcing one active job per asset and analysis type.
WITH ranked_active_jobs AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY
                organization_id,
                media_asset_id,
                job_type
            ORDER BY
                CASE status
                    WHEN 'PROCESSING' THEN 0
                    WHEN 'QUEUED' THEN 1
                    ELSE 2
                END,
                created_at ASC,
                id ASC
        ) AS active_rank
    FROM ai_analysis_jobs
    WHERE media_asset_id IS NOT NULL
      AND status IN (
          'QUEUED',
          'PROCESSING',
          'RETRYING'
      )
)
UPDATE ai_analysis_jobs AS job
SET
    status = 'CANCELLED',
    progress_percentage = 100,
    error_code = 'DUPLICATE_ACTIVE_JOB_CLEANUP',
    error_message =
        'Cancelled while enabling active-job uniqueness',
    cancelled_at = CURRENT_TIMESTAMP,
    completed_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
FROM ranked_active_jobs AS ranked
WHERE job.id = ranked.id
  AND ranked.active_rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS
    uq_ai_jobs_active_media_type
    ON ai_analysis_jobs (
        organization_id,
        media_asset_id,
        job_type
    )
    WHERE media_asset_id IS NOT NULL
      AND status IN (
          'QUEUED',
          'PROCESSING',
          'RETRYING'
      );

CREATE INDEX IF NOT EXISTS idx_ai_jobs_stale_processing
    ON ai_analysis_jobs (
        status,
        updated_at
    )
    WHERE status = 'PROCESSING';

CREATE INDEX IF NOT EXISTS idx_media_assets_retention
    ON media_analysis_assets (
        status,
        analyzed_at
    )
    WHERE deleted_at IS NULL
      AND incident_id IS NULL
      AND evidence_id IS NULL;

-- Encrypted assets created by this backend use a single
-- authenticated format. Existing plaintext assets remain
-- valid and continue to be analyzed after hash verification.
ALTER TABLE media_analysis_assets
    DROP CONSTRAINT IF EXISTS
        chk_media_asset_storage_encryption_algorithm;

ALTER TABLE media_analysis_assets
    ADD CONSTRAINT
        chk_media_asset_storage_encryption_algorithm
        CHECK (
            is_encrypted = false
            OR encryption_algorithm =
                'AES-256-CTR-HMAC-SHA256'
        );

COMMIT;
