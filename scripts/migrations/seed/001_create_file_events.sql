BEGIN;

CREATE TABLE file_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    event_sequence BIGINT GENERATED ALWAYS AS IDENTITY,
    event_code VARCHAR(100) NOT NULL,
    event_fingerprint VARCHAR(64) NOT NULL,

    organization_id UUID NOT NULL,
    department_id UUID,
    monitoring_rule_id UUID,

    protected_file_id UUID,
    honeytoken_id UUID,
    canary_file_id UUID,

    source_type VARCHAR(30) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    event_source VARCHAR(50) NOT NULL,
    detection_method VARCHAR(30) NOT NULL DEFAULT 'RULE_BASED',

    file_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    previous_file_path TEXT,
    file_extension VARCHAR(50),
    mime_type VARCHAR(255),

    file_size_before BIGINT,
    file_size_after BIGINT,

    previous_hash VARCHAR(128),
    current_hash VARCHAR(128),
    hash_algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA256',

    process_id BIGINT,
    process_name VARCHAR(255),
    executable_path TEXT,
    parent_process_id BIGINT,
    parent_process_name VARCHAR(255),
    command_line TEXT,
    process_hash VARCHAR(128),

    system_username VARCHAR(255),
    application_user_id UUID,

    device_name VARCHAR(255),
    device_identifier VARCHAR(255),
    ip_address INET,
    mac_address VARCHAR(50),

    severity VARCHAR(20) NOT NULL DEFAULT 'LOW',
    threat_score INTEGER NOT NULL DEFAULT 0,
    is_suspicious BOOLEAN NOT NULL DEFAULT false,

    status VARCHAR(30) NOT NULL DEFAULT 'RECEIVED',
    processing_error TEXT,

    evidence_copy_path TEXT,
    evidence_hash VARCHAR(128),

    raw_event JSONB,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    occurred_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    received_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_file_event_sequence
        UNIQUE (event_sequence),

    CONSTRAINT uq_file_event_code
        UNIQUE (organization_id, event_code),

    CONSTRAINT uq_file_event_fingerprint
        UNIQUE (organization_id, event_fingerprint),

    CONSTRAINT chk_file_event_source_type
        CHECK (
            source_type IN (
                'PROTECTED_FILE',
                'HONEYTOKEN',
                'CANARY_FILE',
                'UNMANAGED_FILE'
            )
        ),

    CONSTRAINT chk_file_event_type
        CHECK (
            event_type IN (
                'CREATED',
                'OPENED',
                'READ',
                'COPIED',
                'MOVED',
                'RENAMED',
                'MODIFIED',
                'ENCRYPTED',
                'DELETED',
                'EXTENSION_CHANGED',
                'PERMISSION_CHANGED',
                'HASH_CHANGED',
                'MULTIPLE_FILE_CHANGES',
                'CUSTOM'
            )
        ),

    CONSTRAINT chk_file_event_source
        CHECK (
            event_source IN (
                'WINDOWS_WATCHER',
                'LINUX_INOTIFY',
                'MACOS_FSEVENTS',
                'API',
                'AGENT',
                'MANUAL',
                'SYSTEM'
            )
        ),

    CONSTRAINT chk_file_event_detection_method
        CHECK (
            detection_method IN (
                'RULE_BASED',
                'SIGNATURE_BASED',
                'BEHAVIOUR_BASED',
                'AI_BASED',
                'HYBRID'
            )
        ),

    CONSTRAINT chk_file_event_hash_algorithm
        CHECK (
            hash_algorithm IN (
                'SHA256',
                'SHA384',
                'SHA512'
            )
        ),

    CONSTRAINT chk_file_event_severity
        CHECK (
            severity IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    CONSTRAINT chk_file_event_status
        CHECK (
            status IN (
                'RECEIVED',
                'QUEUED',
                'PROCESSING',
                'PROCESSED',
                'FAILED',
                'IGNORED'
            )
        ),

    CONSTRAINT chk_file_event_threat_score
        CHECK (
            threat_score BETWEEN 0 AND 100
        ),

    CONSTRAINT chk_file_event_size_before
        CHECK (
            file_size_before IS NULL
            OR file_size_before >= 0
        ),

    CONSTRAINT chk_file_event_size_after
        CHECK (
            file_size_after IS NULL
            OR file_size_after >= 0
        ),

    CONSTRAINT chk_file_event_process_id
        CHECK (
            process_id IS NULL
            OR process_id >= 0
        ),

    CONSTRAINT chk_file_event_parent_process_id
        CHECK (
            parent_process_id IS NULL
            OR parent_process_id >= 0
        ),

    CONSTRAINT chk_file_event_primary_reference
        CHECK (
            (
                source_type = 'PROTECTED_FILE'
                AND protected_file_id IS NOT NULL
            )
            OR (
                source_type = 'HONEYTOKEN'
                AND honeytoken_id IS NOT NULL
            )
            OR (
                source_type = 'CANARY_FILE'
                AND canary_file_id IS NOT NULL
            )
            OR source_type = 'UNMANAGED_FILE'
        ),

    CONSTRAINT fk_file_event_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_file_event_department
        FOREIGN KEY (department_id)
        REFERENCES departments(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_file_event_monitoring_rule
        FOREIGN KEY (monitoring_rule_id)
        REFERENCES file_monitoring_rules(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_file_event_protected_file
        FOREIGN KEY (protected_file_id)
        REFERENCES protected_files(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_file_event_honeytoken
        FOREIGN KEY (honeytoken_id)
        REFERENCES honeytokens(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_file_event_canary_file
        FOREIGN KEY (canary_file_id)
        REFERENCES canary_files(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_file_event_application_user
        FOREIGN KEY (application_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);

CREATE INDEX idx_file_events_organization
    ON file_events (organization_id);

CREATE INDEX idx_file_events_department
    ON file_events (department_id);

CREATE INDEX idx_file_events_org_occurred
    ON file_events (organization_id, occurred_at DESC);

CREATE INDEX idx_file_events_event_type
    ON file_events (event_type);

CREATE INDEX idx_file_events_source_type
    ON file_events (source_type);

CREATE INDEX idx_file_events_status
    ON file_events (status, occurred_at DESC);

CREATE INDEX idx_file_events_severity
    ON file_events (severity);

CREATE INDEX idx_file_events_monitoring_rule
    ON file_events (monitoring_rule_id);

CREATE INDEX idx_file_events_protected_file
    ON file_events (protected_file_id);

CREATE INDEX idx_file_events_honeytoken
    ON file_events (honeytoken_id);

CREATE INDEX idx_file_events_canary_file
    ON file_events (canary_file_id);

CREATE INDEX idx_file_events_device
    ON file_events (device_identifier);

CREATE INDEX idx_file_events_process
    ON file_events (process_name);

CREATE INDEX idx_file_events_suspicious
    ON file_events (organization_id, occurred_at DESC)
    WHERE is_suspicious = true;

CREATE INDEX idx_file_events_metadata
    ON file_events
    USING GIN (metadata);

CREATE INDEX idx_file_events_occurred_brin
    ON file_events
    USING BRIN (occurred_at);

COMMIT;