CREATE TABLE IF NOT EXISTS dfir_incidents (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'low',
    signals JSONB NOT NULL DEFAULT '[]'::jsonb,
    summary TEXT NOT NULL DEFAULT '',
    assessment JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    evidence_count INTEGER NOT NULL DEFAULT 0,
    timeline_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dfir_evidence (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES dfir_incidents(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dfir_timeline (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES dfir_incidents(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_dfir_incidents_org_created
    ON dfir_incidents (organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_dfir_evidence_incident
    ON dfir_evidence (incident_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_dfir_timeline_incident_time
    ON dfir_timeline (incident_id, timestamp DESC);
