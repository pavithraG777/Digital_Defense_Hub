BEGIN;

CREATE TABLE IF NOT EXISTS security_assets (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    asset_code TEXT NOT NULL,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    hostname TEXT,
    ip_address INET,
    operating_system TEXT,
    owner TEXT,
    criticality TEXT NOT NULL DEFAULT 'MEDIUM',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    tags JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    last_seen_at TIMESTAMPTZ,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, asset_code)
);
CREATE INDEX IF NOT EXISTS idx_security_assets_org_updated
    ON security_assets(organization_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS security_alert_records (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    alert_code TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    payload JSONB NOT NULL DEFAULT '{}',
    acknowledged_by UUID,
    acknowledged_at TIMESTAMPTZ,
    suppressed_by UUID,
    suppressed_at TIMESTAMPTZ,
    suppression_reason TEXT,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, alert_code)
);
CREATE INDEX IF NOT EXISTS idx_security_alert_records_org_status
    ON security_alert_records(organization_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS vulnerability_records (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    asset_id UUID,
    vulnerability_code TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    cvss_score NUMERIC(4,1),
    status TEXT NOT NULL DEFAULT 'OPEN',
    remediation TEXT,
    evidence JSONB NOT NULL DEFAULT '{}',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, vulnerability_code),
    CONSTRAINT fk_vulnerability_asset FOREIGN KEY(asset_id)
        REFERENCES security_assets(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_records_org_status
    ON vulnerability_records(organization_id, status, severity);

CREATE TABLE IF NOT EXISTS compliance_audits (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, framework TEXT NOT NULL,
    scope TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'COMPLETED', score NUMERIC(5,2) NOT NULL,
    passed_checks INTEGER NOT NULL, failed_checks INTEGER NOT NULL,
    checks JSONB NOT NULL DEFAULT '[]', evidence JSONB NOT NULL DEFAULT '{}',
    executed_by UUID NOT NULL, executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_compliance_audits_org_time ON compliance_audits(organization_id,executed_at DESC);

CREATE TABLE IF NOT EXISTS configuration_assessments (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, target_type TEXT NOT NULL,
    target_identifier TEXT NOT NULL, profile TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'COMPLETED',
    score NUMERIC(5,2) NOT NULL, passed_checks INTEGER NOT NULL, failed_checks INTEGER NOT NULL,
    findings JSONB NOT NULL DEFAULT '[]', evidence JSONB NOT NULL DEFAULT '{}',
    assessed_by UUID NOT NULL, assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_configuration_assessments_org_time ON configuration_assessments(organization_id,assessed_at DESC);

CREATE TABLE IF NOT EXISTS access_control_operations (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL,
    permission TEXT NOT NULL, status TEXT NOT NULL, justification TEXT NOT NULL,
    requested_by UUID NOT NULL, granted_by UUID, granted_at TIMESTAMPTZ,
    revoked_by UUID, revoked_at TIMESTAMPTZ, revoke_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_access_control_operations_org_status ON access_control_operations(organization_id,status,created_at DESC);

CREATE TABLE IF NOT EXISTS incident_analytics_snapshots (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE', metrics JSONB NOT NULL,
    generated_by UUID NOT NULL, generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_by UUID, archived_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_incident_analytics_org_time ON incident_analytics_snapshots(organization_id,generated_at DESC);

CREATE TABLE IF NOT EXISTS incident_playbook_executions (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, incident_id UUID NOT NULL,
    playbook_code TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'RECORDED',
    parameters JSONB NOT NULL DEFAULT '{}', result JSONB NOT NULL DEFAULT '{}',
    requested_by UUID NOT NULL, requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT fk_playbook_incident FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_incident_playbook_org_time ON incident_playbook_executions(organization_id,requested_at DESC);

CREATE TABLE IF NOT EXISTS operational_events (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, module TEXT NOT NULL,
    subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, event_type TEXT NOT NULL,
    severity TEXT NOT NULL, risk_score INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'OPEN', payload JSONB NOT NULL DEFAULT '{}',
    created_by UUID NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), resolved_by UUID,
    resolved_at TIMESTAMPTZ, resolution TEXT
);
CREATE INDEX IF NOT EXISTS idx_operational_events_org_module ON operational_events(organization_id,module,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_events_org_risk ON operational_events(organization_id,module,risk_score DESC) WHERE status='OPEN';

CREATE TABLE IF NOT EXISTS operational_actions (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, module TEXT NOT NULL,
    target_type TEXT NOT NULL, target_id TEXT NOT NULL, action_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'REQUESTED', reason TEXT NOT NULL,
    parameters JSONB NOT NULL DEFAULT '{}', result JSONB NOT NULL DEFAULT '{}',
    requested_by UUID NOT NULL, requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_by UUID, completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_operational_actions_org_module ON operational_actions(organization_id,module,requested_at DESC);

CREATE TABLE IF NOT EXISTS usb_devices (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, device_identifier TEXT NOT NULL,
    vendor TEXT, product TEXT, serial_number TEXT, status TEXT NOT NULL DEFAULT 'OBSERVED',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reported_by UUID NOT NULL, metadata JSONB NOT NULL DEFAULT '{}',
    UNIQUE(organization_id,device_identifier)
);
CREATE TABLE IF NOT EXISTS usb_policies (
    organization_id UUID PRIMARY KEY, mode TEXT NOT NULL, allowed_devices JSONB NOT NULL DEFAULT '[]',
    updated_by UUID NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS operational_assessments (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, module TEXT NOT NULL,
    target_type TEXT NOT NULL, target_id TEXT NOT NULL, profile TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'COMPLETED', score INTEGER NOT NULL,
    findings JSONB NOT NULL DEFAULT '[]', evidence JSONB NOT NULL DEFAULT '{}',
    assessed_by UUID NOT NULL, assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_operational_assessments_org_module ON operational_assessments(organization_id,module,assessed_at DESC);

CREATE TABLE IF NOT EXISTS policy_evaluations (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, policy_code TEXT NOT NULL,
    subject JSONB NOT NULL, rules JSONB NOT NULL, decision TEXT NOT NULL,
    reasons JSONB NOT NULL DEFAULT '[]', evaluated_by UUID NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_org_time ON policy_evaluations(organization_id,evaluated_at DESC);

CREATE TABLE IF NOT EXISTS operational_analysis_jobs (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    module TEXT NOT NULL,
    analysis_type TEXT NOT NULL,
    target_uri TEXT NOT NULL,
    file_name TEXT NOT NULL DEFAULT '',
    mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    sha256_hash CHAR(64),
    status TEXT NOT NULL DEFAULT 'AWAITING_EXECUTOR',
    parameters JSONB NOT NULL DEFAULT '{}',
    result JSONB NOT NULL DEFAULT '{}',
    error_code TEXT,
    error_message TEXT,
    requested_by UUID NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    worker_id TEXT,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT operational_analysis_jobs_status_check CHECK
        (status IN ('QUEUED','RUNNING','AWAITING_EXECUTOR','COMPLETED','FAILED','CANCELLED')),
    CONSTRAINT operational_analysis_jobs_sha256_check CHECK
        (sha256_hash IS NULL OR sha256_hash ~ '^[0-9a-fA-F]{64}$')
);
CREATE INDEX IF NOT EXISTS idx_operational_analysis_jobs_org_module
    ON operational_analysis_jobs(organization_id,module,requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_analysis_jobs_claimable
    ON operational_analysis_jobs(organization_id,status,requested_at)
    WHERE status IN ('QUEUED','AWAITING_EXECUTOR','RUNNING');

CREATE TABLE IF NOT EXISTS operational_analysis_job_events (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    job_id UUID NOT NULL REFERENCES operational_analysis_jobs(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    worker_id TEXT,
    details JSONB NOT NULL DEFAULT '{}',
    actor_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_operational_analysis_job_events_job
    ON operational_analysis_job_events(organization_id,job_id,created_at);

COMMIT;
