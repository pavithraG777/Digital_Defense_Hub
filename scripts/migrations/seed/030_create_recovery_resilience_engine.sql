CREATE TABLE IF NOT EXISTS recovery_plans (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, incident_id UUID,
    name TEXT NOT NULL, reason TEXT NOT NULL, idempotency_key TEXT NOT NULL,
    actions JSONB NOT NULL, status TEXT NOT NULL,
    dry_run_result JSONB, created_by UUID NOT NULL, approved_by UUID,
    approved_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_recovery_plans_tenant_status ON recovery_plans(organization_id,status,created_at DESC);

CREATE TABLE IF NOT EXISTS recovery_executions (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL,
    plan_id UUID NOT NULL REFERENCES recovery_plans(id), idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL, result JSONB, rollback_result JSONB,
    attempt_count INTEGER NOT NULL DEFAULT 0, last_error TEXT, requested_by UUID NOT NULL,
    worker_owner TEXT, started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_recovery_executions_queue ON recovery_executions(status,created_at) WHERE status IN ('QUEUED','ROLLBACK_QUEUED');

CREATE TABLE IF NOT EXISTS recovery_controls (
    organization_id UUID PRIMARY KEY, emergency_stop BOOLEAN NOT NULL DEFAULT false,
    reason TEXT, changed_by UUID, changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS recovery_audit_events (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, plan_id UUID, execution_id UUID,
    event_type TEXT NOT NULL, actor_id UUID, details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recovery_audit_tenant_time ON recovery_audit_events(organization_id,created_at DESC);
