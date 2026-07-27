BEGIN;

-- One current organization-scoped authenticity decision per media asset.
-- Specialized deepfake/forensic results remain the source evidence; this
-- table stores only the combined, explainable security verdict.
CREATE TABLE IF NOT EXISTS media_trust_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    media_asset_id UUID NOT NULL,

    trust_score NUMERIC(5, 2) NOT NULL,
    risk_score NUMERIC(5, 2) NOT NULL,
    confidence_score NUMERIC(5, 2) NOT NULL,

    verdict VARCHAR(40) NOT NULL,
    classification VARCHAR(30) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,

    trained_model_used BOOLEAN NOT NULL DEFAULT false,
    requires_human_review BOOLEAN NOT NULL DEFAULT false,
    finalized BOOLEAN NOT NULL DEFAULT false,

    component_scores JSONB NOT NULL DEFAULT '{}'::jsonb,
    signals JSONB NOT NULL DEFAULT '[]'::jsonb,
    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,

    completed_job_count INTEGER NOT NULL DEFAULT 0,
    terminal_job_count INTEGER NOT NULL DEFAULT 0,
    latest_analysis_job_id UUID NULL,

    escalation_status VARCHAR(20) NOT NULL DEFAULT 'NONE',
    escalation_attempt_count INTEGER NOT NULL DEFAULT 0,
    escalation_error TEXT NULL,
    incident_id UUID NULL,
    incident_evidence_id UUID NULL,
    notification_sent_at TIMESTAMP WITHOUT TIME ZONE NULL,
    escalated_at TIMESTAMP WITHOUT TIME ZONE NULL,

    evaluated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_media_trust_assessment_asset
        UNIQUE (organization_id, media_asset_id),

    CONSTRAINT chk_media_trust_score
        CHECK (trust_score >= 0 AND trust_score <= 100),

    CONSTRAINT chk_media_risk_score
        CHECK (risk_score >= 0 AND risk_score <= 100),

    CONSTRAINT chk_media_trust_confidence
        CHECK (confidence_score >= 0 AND confidence_score <= 100),

    CONSTRAINT chk_media_trust_verdict
        CHECK (
            verdict IN (
                'AUTHENTIC',
                'LIKELY_AUTHENTIC',
                'SUSPICIOUS',
                'LIKELY_MANIPULATED',
                'MANIPULATED',
                'INCONCLUSIVE'
            )
        ),

    CONSTRAINT chk_media_trust_classification
        CHECK (
            classification IN (
                'AUTHENTIC',
                'SUSPICIOUS',
                'MANIPULATED',
                'INCONCLUSIVE'
            )
        ),

    CONSTRAINT chk_media_trust_risk_level
        CHECK (
            risk_level IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    CONSTRAINT chk_media_trust_job_counts
        CHECK (
            completed_job_count >= 0
            AND terminal_job_count >= 0
            AND completed_job_count <= terminal_job_count
        ),

    CONSTRAINT chk_media_trust_escalation_status
        CHECK (
            escalation_status IN (
                'NONE',
                'PENDING',
                'IN_PROGRESS',
                'COMPLETED',
                'FAILED'
            )
        ),

    CONSTRAINT chk_media_trust_escalation_attempts
        CHECK (escalation_attempt_count >= 0),

    CONSTRAINT fk_media_trust_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_media_trust_asset
        FOREIGN KEY (media_asset_id)
        REFERENCES media_analysis_assets(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_media_trust_latest_job
        FOREIGN KEY (latest_analysis_job_id)
        REFERENCES ai_analysis_jobs(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_media_trust_incident
        FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_media_trust_incident_evidence
        FOREIGN KEY (incident_evidence_id)
        REFERENCES incident_evidence(id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_media_trust_organization
    ON media_trust_assessments (organization_id, evaluated_at DESC);

CREATE INDEX IF NOT EXISTS idx_media_trust_verdict
    ON media_trust_assessments (
        organization_id,
        verdict,
        risk_level,
        evaluated_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_media_trust_review
    ON media_trust_assessments (
        organization_id,
        requires_human_review,
        evaluated_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_media_trust_escalation
    ON media_trust_assessments (
        escalation_status,
        risk_level,
        evaluated_at
    );

-- Audits organization model/version activation without storing model data
-- outside the existing ai_models and ai_model_versions registry.
CREATE TABLE IF NOT EXISTS ai_model_deployment_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    ai_model_id UUID NOT NULL,
    ai_model_version_id UUID NOT NULL,
    action VARCHAR(30) NOT NULL,
    previous_model_status VARCHAR(30) NULL,
    new_model_status VARCHAR(30) NOT NULL,
    previous_version_status VARCHAR(30) NULL,
    new_version_status VARCHAR(30) NOT NULL,
    activated_by UUID NOT NULL,
    reason TEXT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_ai_model_deployment_action
        CHECK (action IN ('ACTIVATE')),

    CONSTRAINT fk_ai_model_deployment_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ai_model_deployment_model
        FOREIGN KEY (ai_model_id)
        REFERENCES ai_models(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ai_model_deployment_version
        FOREIGN KEY (ai_model_version_id)
        REFERENCES ai_model_versions(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ai_model_deployment_actor
        FOREIGN KEY (activated_by)
        REFERENCES users(id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_ai_model_deployment_audit_model
    ON ai_model_deployment_audit (
        organization_id,
        ai_model_id,
        created_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_ai_model_deployment_audit_actor
    ON ai_model_deployment_audit (
        organization_id,
        activated_by,
        created_at DESC
    );

COMMIT;
