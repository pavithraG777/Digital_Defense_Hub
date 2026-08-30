-- Persisted human-review workflow for deepfake/forensic results.
CREATE TABLE IF NOT EXISTS media_forensic_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    analysis_job_id UUID NOT NULL REFERENCES ai_analysis_jobs(id),
    reviewer_user_id UUID NOT NULL REFERENCES users(id),
    decision VARCHAR(32) NOT NULL CHECK (decision IN ('CONFIRMED_AUTHENTIC','CONFIRMED_MANIPULATED','INCONCLUSIVE','ESCALATED')),
    rationale TEXT NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_media_forensic_reviews_job ON media_forensic_reviews (organization_id, analysis_job_id, reviewed_at DESC);

CREATE TABLE IF NOT EXISTS media_forensic_annotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    analysis_job_id UUID NOT NULL REFERENCES ai_analysis_jobs(id),
    created_by UUID NOT NULL REFERENCES users(id),
    annotation_type VARCHAR(32) NOT NULL CHECK (annotation_type IN ('NOTE','REGION','EVIDENCE','ESCALATION')),
    body TEXT NOT NULL,
    region JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_media_forensic_annotations_job ON media_forensic_annotations (organization_id, analysis_job_id, created_at DESC);

CREATE TABLE IF NOT EXISTS media_forensic_case_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    analysis_job_id UUID NOT NULL REFERENCES ai_analysis_jobs(id),
    investigation_case_id UUID REFERENCES investigation_cases(id),
    incident_id UUID REFERENCES incidents(id),
    linked_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (investigation_case_id IS NOT NULL OR incident_id IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_media_forensic_case_link ON media_forensic_case_links (organization_id, analysis_job_id, COALESCE(investigation_case_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(incident_id, '00000000-0000-0000-0000-000000000000'::uuid));
