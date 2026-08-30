BEGIN;

-- A case is the tenant-owned investigation workspace.  Incidents remain the
-- source of operational truth; cases group one or more incidents and their
-- analyst work without duplicating forensic evidence.
CREATE TABLE IF NOT EXISTS investigation_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    case_number VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
    priority VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    lead_investigator_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    opened_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    opened_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITHOUT TIME ZONE NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITHOUT TIME ZONE NULL,
    CONSTRAINT uq_investigation_cases_number UNIQUE (organization_id, case_number),
    CONSTRAINT chk_investigation_cases_status CHECK (status IN ('OPEN', 'ACTIVE', 'ON_HOLD', 'CLOSED', 'CANCELLED')),
    CONSTRAINT chk_investigation_cases_priority CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'URGENT'))
);

CREATE TABLE IF NOT EXISTS investigation_case_incidents (
    case_id UUID NOT NULL REFERENCES investigation_cases(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
    added_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    added_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (case_id, incident_id),
    CONSTRAINT uq_investigation_case_incident UNIQUE (incident_id)
);

CREATE INDEX IF NOT EXISTS idx_investigation_cases_org_status ON investigation_cases (organization_id, status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_investigation_cases_lead ON investigation_cases (lead_investigator_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_investigation_case_incidents_case ON investigation_case_incidents (case_id);

COMMIT;
