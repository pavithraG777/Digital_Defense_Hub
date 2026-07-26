-- ============================================================
-- FILE NAME : 008_create_adaptive_deception_engine.sql
-- PURPOSE   : Canary health, rotation and interaction
--             fingerprinting support
-- ============================================================

BEGIN;

-- ============================================================
-- 1. CANARY HEALTH CHECKS
-- ============================================================

CREATE TABLE IF NOT EXISTS canary_health_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    health_check_sequence BIGSERIAL NOT NULL UNIQUE,

    organization_id UUID NOT NULL,
    canary_file_id UUID NOT NULL,
    policy_id UUID NULL,

    check_type VARCHAR(40) NOT NULL
        DEFAULT 'SCHEDULED',

    expected_file_path TEXT NOT NULL,
    observed_file_path TEXT NULL,

    expected_hash VARCHAR(128) NOT NULL,
    observed_hash VARCHAR(128) NULL,
    hash_algorithm VARCHAR(20) NOT NULL
        DEFAULT 'SHA256',

    expected_size_bytes BIGINT NULL,
    observed_size_bytes BIGINT NULL,

    file_exists BOOLEAN NOT NULL
        DEFAULT FALSE,

    path_matches BOOLEAN NOT NULL
        DEFAULT FALSE,

    hash_matches BOOLEAN NOT NULL
        DEFAULT FALSE,

    size_matches BOOLEAN NULL,

    permissions_valid BOOLEAN NULL,

    is_healthy BOOLEAN NOT NULL
        DEFAULT FALSE,

    health_score NUMERIC(5, 2) NOT NULL
        DEFAULT 0,

    health_status VARCHAR(30) NOT NULL
        DEFAULT 'UNKNOWN',

    failure_reason TEXT NULL,

    check_metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    checked_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    next_check_at TIMESTAMP WITHOUT TIME ZONE NULL,

    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_canary_health_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_canary_health_canary
        FOREIGN KEY (canary_file_id)
        REFERENCES canary_files(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_canary_health_policy
        FOREIGN KEY (policy_id)
        REFERENCES deception_policies(id)
        ON DELETE SET NULL,

    CONSTRAINT chk_canary_health_check_type
        CHECK (
            check_type IN (
                'STARTUP',
                'SCHEDULED',
                'MANUAL',
                'POST_TRIGGER',
                'POST_ROTATION',
                'RECOVERY'
            )
        ),

    CONSTRAINT chk_canary_health_hash_algorithm
        CHECK (
            hash_algorithm IN (
                'SHA256',
                'SHA384',
                'SHA512'
            )
        ),

    CONSTRAINT chk_canary_health_expected_size
        CHECK (
            expected_size_bytes IS NULL
            OR expected_size_bytes >= 0
        ),

    CONSTRAINT chk_canary_health_observed_size
        CHECK (
            observed_size_bytes IS NULL
            OR observed_size_bytes >= 0
        ),

    CONSTRAINT chk_canary_health_score
        CHECK (
            health_score >= 0
            AND health_score <= 100
        ),

    CONSTRAINT chk_canary_health_status
        CHECK (
            health_status IN (
                'HEALTHY',
                'DEGRADED',
                'TAMPERED',
                'MISSING',
                'EXPIRED',
                'ERROR',
                'UNKNOWN'
            )
        ),

    CONSTRAINT chk_canary_health_next_check
        CHECK (
            next_check_at IS NULL
            OR next_check_at > checked_at
        )
);

CREATE INDEX IF NOT EXISTS
    idx_canary_health_organization
ON canary_health_checks (
    organization_id
);

CREATE INDEX IF NOT EXISTS
    idx_canary_health_canary
ON canary_health_checks (
    canary_file_id,
    checked_at DESC
);

CREATE INDEX IF NOT EXISTS
    idx_canary_health_status
ON canary_health_checks (
    health_status,
    checked_at DESC
);

CREATE INDEX IF NOT EXISTS
    idx_canary_health_next_check
ON canary_health_checks (
    next_check_at
)
WHERE
    next_check_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS
    idx_canary_health_unhealthy
ON canary_health_checks (
    organization_id,
    checked_at DESC
)
WHERE
    is_healthy = FALSE;

CREATE INDEX IF NOT EXISTS
    idx_canary_health_metadata
ON canary_health_checks
USING GIN (
    check_metadata
);

-- ============================================================
-- 2. CANARY ROTATION HISTORY
-- ============================================================

CREATE TABLE IF NOT EXISTS canary_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    rotation_sequence BIGSERIAL NOT NULL UNIQUE,

    organization_id UUID NOT NULL,
    canary_file_id UUID NOT NULL,
    policy_id UUID NULL,

    rotation_reason VARCHAR(40) NOT NULL,

    rotation_strategy VARCHAR(40) NOT NULL,

    old_file_name VARCHAR(255) NULL,
    new_file_name VARCHAR(255) NULL,

    old_file_path TEXT NULL,
    new_file_path TEXT NULL,

    old_file_hash VARCHAR(128) NULL,
    new_file_hash VARCHAR(128) NULL,

    old_tracking_identifier VARCHAR(255) NULL,
    new_tracking_identifier VARCHAR(255) NULL,

    status VARCHAR(30) NOT NULL
        DEFAULT 'PENDING',

    requested_by UUID NULL,

    error_message TEXT NULL,

    rotation_metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    requested_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    started_at TIMESTAMP WITHOUT TIME ZONE NULL,

    completed_at TIMESTAMP WITHOUT TIME ZONE NULL,

    failed_at TIMESTAMP WITHOUT TIME ZONE NULL,

    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_canary_rotation_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_canary_rotation_canary
        FOREIGN KEY (canary_file_id)
        REFERENCES canary_files(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_canary_rotation_policy
        FOREIGN KEY (policy_id)
        REFERENCES deception_policies(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_canary_rotation_requested_by
        FOREIGN KEY (requested_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    CONSTRAINT chk_canary_rotation_reason
        CHECK (
            rotation_reason IN (
                'SCHEDULED',
                'MANUAL',
                'TRIGGERED',
                'TAMPERED',
                'MISSING',
                'EXPIRED',
                'POLICY_CHANGED',
                'HEALTH_DEGRADED'
            )
        ),

    CONSTRAINT chk_canary_rotation_strategy
        CHECK (
            rotation_strategy IN (
                'RENAME',
                'RELOCATE',
                'REGENERATE',
                'REDEPLOY',
                'REGENERATE_AND_RELOCATE'
            )
        ),

    CONSTRAINT chk_canary_rotation_status
        CHECK (
            status IN (
                'PENDING',
                'PROCESSING',
                'COMPLETED',
                'FAILED',
                'CANCELLED'
            )
        ),

    CONSTRAINT chk_canary_rotation_completion
        CHECK (
            status <> 'COMPLETED'
            OR completed_at IS NOT NULL
        ),

    CONSTRAINT chk_canary_rotation_failure
        CHECK (
            status <> 'FAILED'
            OR failed_at IS NOT NULL
        )
);

CREATE INDEX IF NOT EXISTS
    idx_canary_rotations_organization
ON canary_rotations (
    organization_id
);

CREATE INDEX IF NOT EXISTS
    idx_canary_rotations_canary
ON canary_rotations (
    canary_file_id,
    requested_at DESC
);

CREATE INDEX IF NOT EXISTS
    idx_canary_rotations_status
ON canary_rotations (
    status,
    requested_at
);

CREATE INDEX IF NOT EXISTS
    idx_canary_rotations_reason
ON canary_rotations (
    rotation_reason,
    requested_at DESC
);

CREATE UNIQUE INDEX IF NOT EXISTS
    uq_canary_active_rotation
ON canary_rotations (
    canary_file_id
)
WHERE
    status IN (
        'PENDING',
        'PROCESSING'
    );

CREATE INDEX IF NOT EXISTS
    idx_canary_rotation_metadata
ON canary_rotations
USING GIN (
    rotation_metadata
);

-- ============================================================
-- 3. CANARY INTERACTION FINGERPRINTS
-- ============================================================

CREATE TABLE IF NOT EXISTS
    canary_interaction_fingerprints (
        id UUID PRIMARY KEY
            DEFAULT gen_random_uuid(),

        fingerprint_sequence BIGSERIAL
            NOT NULL UNIQUE,

        organization_id UUID NOT NULL,
        canary_file_id UUID NOT NULL,

        access_log_id UUID NULL,
        file_event_id UUID NULL,

        fingerprint_hash VARCHAR(64) NOT NULL,
        fingerprint_version VARCHAR(20) NOT NULL
            DEFAULT '1.0.0',

        event_type VARCHAR(60) NOT NULL,

        device_identifier VARCHAR(255) NULL,
        device_name VARCHAR(255) NULL,

        operating_system VARCHAR(100) NULL,
        operating_system_user VARCHAR(255) NULL,

        process_name VARCHAR(255) NULL,
        process_path TEXT NULL,
        process_id BIGINT NULL,

        parent_process_name VARCHAR(255) NULL,

        source_ip INET NULL,

        interaction_pattern JSONB NOT NULL
            DEFAULT '{}'::jsonb,

        behavioural_score NUMERIC(5, 2)
            NOT NULL DEFAULT 0,

        confidence_score NUMERIC(5, 2)
            NOT NULL DEFAULT 0,

        is_suspicious BOOLEAN NOT NULL
            DEFAULT TRUE,

        ransomware_suspected BOOLEAN NOT NULL
            DEFAULT FALSE,

        occurrence_count INTEGER NOT NULL
            DEFAULT 1,

        first_observed_at
            TIMESTAMP WITHOUT TIME ZONE NOT NULL,

        last_observed_at
            TIMESTAMP WITHOUT TIME ZONE NOT NULL,

        created_at
            TIMESTAMP WITHOUT TIME ZONE NOT NULL
            DEFAULT CURRENT_TIMESTAMP,

        updated_at
            TIMESTAMP WITHOUT TIME ZONE NOT NULL
            DEFAULT CURRENT_TIMESTAMP,

        CONSTRAINT fk_canary_fingerprint_organization
            FOREIGN KEY (organization_id)
            REFERENCES organizations(id)
            ON DELETE CASCADE,

        CONSTRAINT fk_canary_fingerprint_canary
            FOREIGN KEY (canary_file_id)
            REFERENCES canary_files(id)
            ON DELETE CASCADE,

        CONSTRAINT fk_canary_fingerprint_access_log
            FOREIGN KEY (access_log_id)
            REFERENCES canary_file_access_logs(id)
            ON DELETE SET NULL,

        CONSTRAINT fk_canary_fingerprint_file_event
            FOREIGN KEY (file_event_id)
            REFERENCES file_events(id)
            ON DELETE SET NULL,

        CONSTRAINT uq_canary_interaction_fingerprint
            UNIQUE (
                organization_id,
                fingerprint_hash
            ),

        CONSTRAINT chk_canary_fingerprint_hash
            CHECK (
                fingerprint_hash ~
                    '^[0-9a-f]{64}$'
            ),

        CONSTRAINT chk_canary_behavioural_score
            CHECK (
                behavioural_score >= 0
                AND behavioural_score <= 100
            ),

        CONSTRAINT chk_canary_fingerprint_confidence
            CHECK (
                confidence_score >= 0
                AND confidence_score <= 100
            ),

        CONSTRAINT chk_canary_fingerprint_occurrences
            CHECK (
                occurrence_count >= 1
            ),

        CONSTRAINT chk_canary_fingerprint_process_id
            CHECK (
                process_id IS NULL
                OR process_id >= 0
            ),

        CONSTRAINT chk_canary_fingerprint_window
            CHECK (
                last_observed_at >=
                    first_observed_at
            )
    );

CREATE INDEX IF NOT EXISTS
    idx_canary_fingerprints_organization
ON canary_interaction_fingerprints (
    organization_id,
    last_observed_at DESC
);

CREATE INDEX IF NOT EXISTS
    idx_canary_fingerprints_canary
ON canary_interaction_fingerprints (
    canary_file_id,
    last_observed_at DESC
);

CREATE INDEX IF NOT EXISTS
    idx_canary_fingerprints_device
ON canary_interaction_fingerprints (
    device_identifier
);

CREATE INDEX IF NOT EXISTS
    idx_canary_fingerprints_process
ON canary_interaction_fingerprints (
    process_name
);

CREATE INDEX IF NOT EXISTS
    idx_canary_fingerprints_suspicious
ON canary_interaction_fingerprints (
    organization_id,
    last_observed_at DESC
)
WHERE
    is_suspicious = TRUE;

CREATE INDEX IF NOT EXISTS
    idx_canary_fingerprint_pattern
ON canary_interaction_fingerprints
USING GIN (
    interaction_pattern
);

COMMIT;