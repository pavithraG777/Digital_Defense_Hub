CREATE TABLE IF NOT EXISTS ransomware_scans (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    requested_by UUID NOT NULL REFERENCES users(id),
    folder_name VARCHAR(255) NOT NULL,
    total_files INTEGER NOT NULL CHECK (total_files >= 0),
    suspicious_files INTEGER NOT NULL CHECK (suspicious_files >= 0),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    verdict VARCHAR(32) NOT NULL,
    findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ransomware_scans_org_completed ON ransomware_scans (organization_id, completed_at DESC);
