
BEGIN;

CREATE TABLE threats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    threat_sequence BIGINT GENERATED ALWAYS AS IDENTITY,
    threat_code VARCHAR(100) NOT NULL,
    correlation_key VARCHAR(128) NOT NULL,

    organization_id UUID NOT NULL,
    department_id UUID,

    primary_event_id UUID NOT NULL,
    monitoring_rule_id UUID,

    protected_file_id UUID,
    honeytoken_id UUID,
    canary_file_id UUID,

    threat_type VARCHAR(50) NOT NULL,
    threat_category VARCHAR(50) NOT NULL,
    detection_method VARCHAR(30) NOT NULL DEFAULT 'RULE_BASED',

    title VARCHAR(255) NOT NULL,
    description TEXT,

    severity VARCHAR(20) NOT NULL,
    threat_score INTEGER NOT NULL,
    confidence_score NUMERIC(5,2) NOT NULL DEFAULT 0,

    classification VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN',
    status VARCHAR(30) NOT NULL DEFAULT 'DETECTED',

    occurrence_count INTEGER NOT NULL DEFAULT 1,
    affected_file_count INTEGER NOT NULL DEFAULT 1,
    affected_device_count INTEGER NOT NULL DEFAULT 1,

    source_process_name VARCHAR(255),
    source_process_id BIGINT,
    source_device_name VARCHAR(255),
    source_device_identifier VARCHAR(255),

    indicators JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_factors JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence_summary JSONB NOT NULL DEFAULT '{}'::jsonb,

    recommended_action TEXT,
    mitigation_action TEXT,

    is_auto_generated BOOLEAN NOT NULL DEFAULT true,

    first_detected_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    last_detected_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,

    confirmed_at TIMESTAMP WITHOUT TIME ZONE,
    mitigated_at TIMESTAMP WITHOUT TIME ZONE,
    resolved_at TIMESTAMP WITHOUT TIME ZONE,

    assigned_to UUID,
    confirmed_by UUID,
    created_by UUID,
    updated_by UUID,

    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITHOUT TIME ZONE,

    CONSTRAINT uq_threat_sequence
        UNIQUE (threat_sequence),

    CONSTRAINT uq_threat_code
        UNIQUE (organization_id, threat_code),

    CONSTRAINT uq_threat_correlation
        UNIQUE (organization_id, correlation_key),

    CONSTRAINT chk_threat_type
        CHECK (
            threat_type IN (
                'HONEYTOKEN_ACCESS',
                'CANARY_TRIGGERED',
                'FILE_TAMPERING',
                'MASS_FILE_MODIFICATION',
                'MASS_FILE_RENAME',
                'MASS_FILE_DELETION',
                'RANSOMWARE_ACTIVITY',
                'UNAUTHORIZED_ACCESS',
                'SUSPICIOUS_PROCESS',
                'HASH_MISMATCH',
                'PERMISSION_ABUSE',
                'CUSTOM'
            )
        ),

    CONSTRAINT chk_threat_category
        CHECK (
            threat_category IN (
                'DECEPTION',
                'RANSOMWARE',
                'INTEGRITY',
                'ACCESS_CONTROL',
                'MALWARE',
                'BEHAVIOURAL_ANOMALY',
                'UNKNOWN'
            )
        ),

    CONSTRAINT chk_threat_detection_method
        CHECK (
            detection_method IN (
                'RULE_BASED',
                'SIGNATURE_BASED',
                'BEHAVIOUR_BASED',
                'AI_BASED',
                'HYBRID'
            )
        ),

    CONSTRAINT chk_threat_severity
        CHECK (
            severity IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    CONSTRAINT chk_threat_score
        CHECK (
            threat_score BETWEEN 0 AND 100
        ),

    CONSTRAINT chk_threat_confidence
        CHECK (
            confidence_score BETWEEN 0 AND 100
        ),

    CONSTRAINT chk_threat_classification
        CHECK (
            classification IN (
                'UNKNOWN',
                'LIKELY_BENIGN',
                'SUSPICIOUS',
                'LIKELY_MALICIOUS',
                'MALICIOUS'
            )
        ),

    CONSTRAINT chk_threat_status
        CHECK (
            status IN (
                'DETECTED',
                'ANALYZING',
                'CONFIRMED',
                'FALSE_POSITIVE',
                'MITIGATED',
                'ESCALATED',
                'RESOLVED',
                'ARCHIVED'
            )
        ),

    CONSTRAINT chk_threat_occurrence_count
        CHECK (
            occurrence_count >= 1
        ),

    CONSTRAINT chk_threat_affected_file_count
        CHECK (
            affected_file_count >= 0
        ),

    CONSTRAINT chk_threat_affected_device_count
        CHECK (
            affected_device_count >= 0
        ),

    CONSTRAINT chk_threat_source_process_id
        CHECK (
            source_process_id IS NULL
            OR source_process_id >= 0
        ),

    CONSTRAINT chk_threat_detection_times
        CHECK (
            last_detected_at >= first_detected_at
        ),

    CONSTRAINT fk_threat_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_threat_department
        FOREIGN KEY (department_id)
        REFERENCES departments(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_threat_primary_event
        FOREIGN KEY (primary_event_id)
        REFERENCES file_events(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_threat_monitoring_rule
        FOREIGN KEY (monitoring_rule_id)
        REFERENCES file_monitoring_rules(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_threat_protected_file
        FOREIGN KEY (protected_file_id)
        REFERENCES protected_files(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_threat_honeytoken
        FOREIGN KEY (honeytoken_id)
        REFERENCES honeytokens(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_threat_canary_file
        FOREIGN KEY (canary_file_id)
        REFERENCES canary_files(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_threat_assigned_to
        FOREIGN KEY (assigned_to)
        REFERENCES users(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_threat_confirmed_by
        FOREIGN KEY (confirmed_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_threat_created_by
        FOREIGN KEY (created_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_threat_updated_by
        FOREIGN KEY (updated_by)
        REFERENCES users(id)
        ON DELETE SET NULL
);

CREATE TABLE threat_file_events (
    threat_id UUID NOT NULL,
    file_event_id UUID NOT NULL,

    relation_type VARCHAR(30) NOT NULL DEFAULT 'SUPPORTING',
    added_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_threat_file_events
        PRIMARY KEY (threat_id, file_event_id),

    CONSTRAINT chk_threat_file_event_relation
        CHECK (
            relation_type IN (
                'PRIMARY',
                'SUPPORTING',
                'CORRELATED',
                'EVIDENCE'
            )
        ),

    CONSTRAINT fk_threat_file_event_threat
        FOREIGN KEY (threat_id)
        REFERENCES threats(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_threat_file_event_event
        FOREIGN KEY (file_event_id)
        REFERENCES file_events(id)
        ON DELETE RESTRICT
);

CREATE INDEX idx_threats_organization
    ON threats (organization_id);

CREATE INDEX idx_threats_department
    ON threats (department_id);

CREATE INDEX idx_threats_primary_event
    ON threats (primary_event_id);

CREATE INDEX idx_threats_monitoring_rule
    ON threats (monitoring_rule_id);

CREATE INDEX idx_threats_type
    ON threats (threat_type);

CREATE INDEX idx_threats_category
    ON threats (threat_category);

CREATE INDEX idx_threats_detection_method
    ON threats (detection_method);

CREATE INDEX idx_threats_status
    ON threats (status);

CREATE INDEX idx_threats_severity
    ON threats (severity);

CREATE INDEX idx_threats_score
    ON threats (threat_score DESC);

CREATE INDEX idx_threats_last_detected
    ON threats (last_detected_at DESC);

CREATE INDEX idx_threats_org_last_detected
    ON threats (
        organization_id,
        last_detected_at DESC
    );

CREATE INDEX idx_threats_protected_file
    ON threats (protected_file_id);

CREATE INDEX idx_threats_honeytoken
    ON threats (honeytoken_id);

CREATE INDEX idx_threats_canary_file
    ON threats (canary_file_id);

CREATE INDEX idx_threats_assigned_to
    ON threats (assigned_to);

CREATE INDEX idx_threats_open_critical
    ON threats (
        organization_id,
        last_detected_at DESC
    )
    WHERE
        severity = 'CRITICAL'
        AND status IN (
            'DETECTED',
            'ANALYZING',
            'CONFIRMED',
            'ESCALATED'
        )
        AND deleted_at IS NULL;

CREATE INDEX idx_threats_indicators
    ON threats
    USING GIN (indicators);

CREATE INDEX idx_threats_risk_factors
    ON threats
    USING GIN (risk_factors);

CREATE INDEX idx_threat_file_events_event
    ON threat_file_events (file_event_id);

COMMIT;





SELECT
    table_name,
    COUNT(*) AS column_count
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name IN (
      'threats',
      'threat_file_events'
  )
GROUP BY table_name
ORDER BY table_name;
