-- ============================================================
-- FILE NAME  : 006_create_ai_risk_scores.sql
-- PURPOSE    : Create AI risk score storage and indexes
-- PROJECT    : Offline-First Cyber Security and
--              Digital Forensics Platform
-- ============================================================

BEGIN;

CREATE TABLE IF NOT EXISTS ai_risk_scores (
    id UUID NOT NULL DEFAULT gen_random_uuid(),

    organization_id UUID NOT NULL,
    analysis_job_id UUID,
    incident_id UUID,
    alert_id UUID,
    evidence_id UUID,

    risk_subject_type VARCHAR(50) NOT NULL,
    risk_subject_id UUID NOT NULL,

    overall_risk_score NUMERIC(5, 2) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,

    threat_probability NUMERIC(5, 2),
    integrity_risk_score NUMERIC(5, 2),
    confidentiality_risk_score NUMERIC(5, 2),
    availability_risk_score NUMERIC(5, 2),
    confidence_score NUMERIC(5, 2),

    risk_factors JSONB,
    score_explanation TEXT,
    recommended_action TEXT,

    requires_human_review BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',

    calculated_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMP WITHOUT TIME ZONE,

    created_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ai_risk_scores_pkey
        PRIMARY KEY (id),

    CONSTRAINT fk_ai_risk_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ai_risk_job
        FOREIGN KEY (analysis_job_id)
        REFERENCES ai_analysis_jobs(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_ai_risk_incident
        FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ai_risk_alert
        FOREIGN KEY (alert_id)
        REFERENCES security_alerts(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_ai_risk_evidence
        FOREIGN KEY (evidence_id)
        REFERENCES evidence_items(id)
        ON DELETE CASCADE,

    CONSTRAINT ai_risk_scores_risk_subject_type_check
        CHECK (
            risk_subject_type IN (
                'INCIDENT',
                'SECURITY_ALERT',
                'EVIDENCE',
                'EVIDENCE_FILE',
                'USER',
                'DEVICE',
                'AI_ANALYSIS_JOB'
            )
        ),

    CONSTRAINT ai_risk_scores_overall_risk_score_check
        CHECK (
            overall_risk_score >= 0
            AND overall_risk_score <= 100
        ),

    CONSTRAINT ai_risk_scores_risk_level_check
        CHECK (
            risk_level IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    CONSTRAINT ai_risk_scores_threat_probability_check
        CHECK (
            threat_probability IS NULL
            OR (
                threat_probability >= 0
                AND threat_probability <= 100
            )
        ),

    CONSTRAINT ai_risk_scores_integrity_risk_score_check
        CHECK (
            integrity_risk_score IS NULL
            OR (
                integrity_risk_score >= 0
                AND integrity_risk_score <= 100
            )
        ),

    CONSTRAINT ai_risk_scores_confidentiality_risk_score_check
        CHECK (
            confidentiality_risk_score IS NULL
            OR (
                confidentiality_risk_score >= 0
                AND confidentiality_risk_score <= 100
            )
        ),

    CONSTRAINT ai_risk_scores_availability_risk_score_check
        CHECK (
            availability_risk_score IS NULL
            OR (
                availability_risk_score >= 0
                AND availability_risk_score <= 100
            )
        ),

    CONSTRAINT ai_risk_scores_confidence_score_check
        CHECK (
            confidence_score IS NULL
            OR (
                confidence_score >= 0
                AND confidence_score <= 100
            )
        ),

    CONSTRAINT ai_risk_scores_status_check
        CHECK (
            status IN (
                'ACTIVE',
                'REVIEWED',
                'OVERRIDDEN',
                'EXPIRED',
                'ARCHIVED'
            )
        ),

    CONSTRAINT chk_ai_risk_expiry
        CHECK (
            expires_at IS NULL
            OR expires_at > calculated_at
        )
);

CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_organization
    ON ai_risk_scores (organization_id);

CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_job
    ON ai_risk_scores (analysis_job_id);

CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_incident
    ON ai_risk_scores (incident_id);

CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_alert
    ON ai_risk_scores (alert_id);

CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_evidence
    ON ai_risk_scores (evidence_id);

CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_subject
    ON ai_risk_scores (
        risk_subject_type,
        risk_subject_id
    );

CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_level
    ON ai_risk_scores (risk_level);

CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_status
    ON ai_risk_scores (status);

CREATE INDEX IF NOT EXISTS idx_ai_risk_scores_calculated_at
    ON ai_risk_scores (calculated_at);

COMMIT;