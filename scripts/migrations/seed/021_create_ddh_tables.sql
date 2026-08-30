-- Create tables for DDH DDH-specific modules: lateral movement, credential abuse, evidence vault

CREATE TABLE IF NOT EXISTS lateral_movement_alerts (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    device_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credential_events (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS evidence_preservation_jobs (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    items JSONB NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS privilege_escalation_detections (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    host TEXT NOT NULL,
    user_id UUID NOT NULL,
    detection_type TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Attack story engine
CREATE TABLE IF NOT EXISTS attack_stories (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    title TEXT NOT NULL,
    timeline JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Incident engine stories
CREATE TABLE IF NOT EXISTS incident_engine_stories (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    title TEXT NOT NULL,
    timeline JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Baseline anomalies
CREATE TABLE IF NOT EXISTS baseline_anomalies (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    metric TEXT NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Threat correlation results (indexed by correlation id)
CREATE TABLE IF NOT EXISTS threat_correlations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    correlation_type TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
