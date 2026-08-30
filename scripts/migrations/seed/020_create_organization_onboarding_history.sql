CREATE TABLE IF NOT EXISTS organization_onboarding_details (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    registration_number VARCHAR(120), website VARCHAR(255), phone VARCHAR(40), address TEXT,
    admin_name VARCHAR(160), admin_designation VARCHAR(120), admin_email VARCHAR(320), admin_phone VARCHAR(40),
    purpose TEXT, estimated_users INTEGER, security_level VARCHAR(40), created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS organization_approval_history (
    id BIGSERIAL PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    action VARCHAR(40) NOT NULL, reason TEXT, actor_id UUID NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS organization_approval_history_organization_created_idx ON organization_approval_history (organization_id, created_at DESC);
