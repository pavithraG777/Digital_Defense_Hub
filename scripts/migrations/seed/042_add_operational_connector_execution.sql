BEGIN;

ALTER TABLE operational_actions
    ADD COLUMN IF NOT EXISTS worker_id TEXT,
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS error_code TEXT,
    ADD COLUMN IF NOT EXISTS error_message TEXT;

CREATE TABLE IF NOT EXISTS operational_action_events (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    action_id UUID NOT NULL REFERENCES operational_actions(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    worker_id TEXT,
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_operational_action_events_action
    ON operational_action_events(organization_id,action_id,created_at);
CREATE INDEX IF NOT EXISTS idx_operational_actions_connector_claim
    ON operational_actions(module,status,requested_at)
    WHERE status IN ('REQUESTED','RUNNING');

COMMIT;
