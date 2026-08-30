CREATE TABLE IF NOT EXISTS threat_intelligence_jobs (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL, indicator_type TEXT NOT NULL,
 indicator_value TEXT NOT NULL, normalized_value TEXT NOT NULL, idempotency_key TEXT NOT NULL,
 status TEXT NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, worker_owner TEXT,
 last_error TEXT, result JSONB, started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(organization_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_jobs_queue ON threat_intelligence_jobs(status,created_at) WHERE status IN('QUEUED','RUNNING');
CREATE TABLE IF NOT EXISTS threat_intelligence_provider_observations (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL, job_id UUID NOT NULL REFERENCES threat_intelligence_jobs(id),
 provider TEXT NOT NULL, source_reference TEXT NOT NULL, indicator_type TEXT NOT NULL, normalized_value TEXT NOT NULL,
 reputation INTEGER NOT NULL CHECK(reputation BETWEEN 0 AND 100), confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
 first_seen_at TIMESTAMPTZ, last_seen_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
 raw JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(organization_id,provider,source_reference,indicator_type,normalized_value)
);
