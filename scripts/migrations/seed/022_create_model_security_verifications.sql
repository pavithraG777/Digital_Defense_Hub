BEGIN;

CREATE TABLE IF NOT EXISTS model_security_verifications (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    model_id TEXT NOT NULL,
    model_version TEXT NOT NULL,
    expected_sha256 CHAR(64) NOT NULL,
    observed_sha256 CHAR(64) NOT NULL,
    attestation_issuer TEXT,
    attestation_reference TEXT,
    validation_passed BOOLEAN NOT NULL,
    integrity_verified BOOLEAN NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('VERIFIED', 'BLOCKED')),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL,
    requires_review BOOLEAN NOT NULL,
    risk_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
    summary TEXT NOT NULL,
    verified_by UUID NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_security_org_time
    ON model_security_verifications (organization_id, verified_at DESC);

INSERT INTO permissions (permission_code, permission_name, module_name, action_name, description, risk_level, requires_approval, status)
VALUES
    ('MODEL_SECURITY_VIEW', 'View Model Security', 'MODEL_SECURITY', 'VIEW', 'View model integrity and verification evidence.', 'MEDIUM', FALSE, 'ACTIVE'),
    ('MODEL_SECURITY_MANAGE', 'Manage Model Security', 'MODEL_SECURITY', 'MANAGE', 'Verify model artifacts and record deployment-gate decisions.', 'CRITICAL', TRUE, 'ACTIVE')
ON CONFLICT (permission_code) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at, expires_at, is_active)
SELECT r.id, p.id, NULL, CURRENT_TIMESTAMP, NULL, TRUE
FROM roles r
JOIN permissions p ON p.permission_code IN ('MODEL_SECURITY_VIEW', 'MODEL_SECURITY_MANAGE')
WHERE r.role_code IN ('SUPER_ADMIN', 'ORG_ADMIN', 'AI_ANALYST')
  AND r.deleted_at IS NULL
ON CONFLICT DO NOTHING;

COMMIT;
