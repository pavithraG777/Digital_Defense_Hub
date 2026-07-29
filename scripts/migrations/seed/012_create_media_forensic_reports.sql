BEGIN;

CREATE TABLE IF NOT EXISTS media_forensic_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    media_asset_id UUID NOT NULL,
    incident_id UUID NULL REFERENCES incidents(id) ON DELETE SET NULL,
    report_number VARCHAR(80) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'GENERATED'
        CHECK (status IN ('GENERATED', 'APPROVED')),
    report_data JSONB NOT NULL,
    document_pdf BYTEA NOT NULL,
    document_sha256 VARCHAR(64) NOT NULL,
    generated_by UUID NOT NULL REFERENCES users(id),
    generated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_by UUID NULL REFERENCES users(id),
    approved_at TIMESTAMP WITHOUT TIME ZONE NULL,
    approval_note TEXT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_media_forensic_reports_org_asset
        UNIQUE (organization_id, media_asset_id)
);

CREATE INDEX IF NOT EXISTS idx_media_forensic_reports_org_generated
    ON media_forensic_reports (organization_id, generated_at DESC);

COMMIT;
