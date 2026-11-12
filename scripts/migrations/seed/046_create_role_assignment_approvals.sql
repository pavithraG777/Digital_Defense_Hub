CREATE TABLE IF NOT EXISTS role_assignment_approvals (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id), user_ids UUID[] NOT NULL, role_ids UUID[] NOT NULL,
 expires_at TIMESTAMPTZ, reason TEXT NOT NULL, status VARCHAR(16) NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','APPROVED','REJECTED')),
 requested_by UUID NOT NULL REFERENCES users(id), decided_by UUID REFERENCES users(id), decision_note TEXT,
 requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), decided_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_role_assignment_approvals_org_status ON role_assignment_approvals(organization_id,status,requested_at DESC);
