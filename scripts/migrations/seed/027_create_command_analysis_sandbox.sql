BEGIN;
CREATE TABLE IF NOT EXISTS command_analysis_results(id UUID PRIMARY KEY,organization_id UUID NOT NULL,language TEXT NOT NULL,script_sha256 CHAR(64) NOT NULL,artifact_uri TEXT,analysis JSONB NOT NULL,signature_version INTEGER NOT NULL,created_by UUID,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS command_sandbox_jobs(id UUID PRIMARY KEY,organization_id UUID NOT NULL,analysis_id UUID NOT NULL,status TEXT NOT NULL DEFAULT 'QUEUED',isolation_profile TEXT NOT NULL,attempt_count INTEGER NOT NULL DEFAULT 0,result JSONB,last_error TEXT,created_by UUID,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),started_at TIMESTAMPTZ,completed_at TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS idx_command_sandbox_claim ON command_sandbox_jobs(status,created_at);
COMMIT;
