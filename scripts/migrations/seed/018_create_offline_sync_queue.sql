-- Offline-first synchronization outbox. Payloads stay organization scoped and
-- are claimed atomically by an authorized sync client when connectivity returns.
CREATE TABLE IF NOT EXISTS offline_sync_queue (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    sync_type varchar(40) NOT NULL CHECK (sync_type IN ('PENDING_DATA','THREAT_INTELLIGENCE','AI_MODEL','CASE_TRANSFER','BACKUP')),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    checksum_sha256 varchar(64),
    status varchar(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','FAILED','CANCELLED')),
    retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    last_error text,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    claimed_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_offline_sync_queue_claim
    ON offline_sync_queue (organization_id, status, created_at);
