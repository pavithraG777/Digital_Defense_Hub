BEGIN;

-- Links one incident with one or more correlated threats.
CREATE TABLE IF NOT EXISTS incident_threats (
    incident_id UUID NOT NULL,
    threat_id UUID NOT NULL,
    relation_type VARCHAR(30) NOT NULL DEFAULT 'PRIMARY',
    added_by UUID NULL,
    added_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_incident_threats
        PRIMARY KEY (incident_id, threat_id),

    CONSTRAINT uq_incident_threats_threat
        UNIQUE (threat_id),

    CONSTRAINT chk_incident_threat_relation
        CHECK (
            relation_type IN (
                'PRIMARY',
                'RELATED',
                'SUPPORTING'
            )
        ),

    CONSTRAINT fk_incident_threat_incident
        FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_incident_threat_threat
        FOREIGN KEY (threat_id)
        REFERENCES threats(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_incident_threat_added_by
        FOREIGN KEY (added_by)
        REFERENCES users(id)
        ON DELETE SET NULL
);

-- Stores the complete chronological investigation history.
CREATE TABLE IF NOT EXISTS incident_timeline (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL,
    organization_id UUID NOT NULL,

    event_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,

    previous_status VARCHAR(30) NULL,
    new_status VARCHAR(30) NULL,

    actor_user_id UUID NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    occurred_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_incident_timeline_event_type
        CHECK (
            event_type IN (
                'CREATED',
                'THREAT_LINKED',
                'ASSIGNED',
                'STATUS_CHANGED',
                'INVESTIGATION_UPDATED',
                'CONTAINMENT_ACTION',
                'EVIDENCE_ADDED',
                'NOTE_ADDED',
                'SYSTEM_ACTION'
            )
        ),

    CONSTRAINT chk_incident_timeline_previous_status
        CHECK (
            previous_status IS NULL
            OR previous_status IN (
                'OPEN',
                'ASSIGNED',
                'INVESTIGATING',
                'CONTAINED',
                'ERADICATED',
                'RECOVERING',
                'RESOLVED',
                'CLOSED',
                'REOPENED',
                'CANCELLED'
            )
        ),

    CONSTRAINT chk_incident_timeline_new_status
        CHECK (
            new_status IS NULL
            OR new_status IN (
                'OPEN',
                'ASSIGNED',
                'INVESTIGATING',
                'CONTAINED',
                'ERADICATED',
                'RECOVERING',
                'RESOLVED',
                'CLOSED',
                'REOPENED',
                'CANCELLED'
            )
        ),

    CONSTRAINT fk_incident_timeline_incident
        FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_incident_timeline_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_incident_timeline_actor
        FOREIGN KEY (actor_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);

-- Stores incident evidence metadata and integrity verification information.
CREATE TABLE IF NOT EXISTS incident_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL,
    organization_id UUID NOT NULL,

    evidence_code VARCHAR(100) NOT NULL,
    evidence_type VARCHAR(50) NOT NULL,
    evidence_name VARCHAR(255) NOT NULL,
    description TEXT NULL,

    threat_id UUID NULL,
    file_event_id UUID NULL,
    protected_file_id UUID NULL,
    honeytoken_id UUID NULL,
    canary_file_id UUID NULL,

    storage_path TEXT NULL,
    original_file_name VARCHAR(255) NULL,
    mime_type VARCHAR(255) NULL,
    file_size_bytes BIGINT NULL,

    evidence_hash VARCHAR(128) NULL,
    hash_algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA256',
    integrity_status VARCHAR(30) NOT NULL DEFAULT 'PENDING',

    is_immutable BOOLEAN NOT NULL DEFAULT true,

    collected_by UUID NULL,
    verified_by UUID NULL,
    collected_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP WITHOUT TIME ZONE NULL,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITHOUT TIME ZONE NULL,

    CONSTRAINT uq_incident_evidence_code
        UNIQUE (organization_id, evidence_code),

    CONSTRAINT chk_incident_evidence_type
        CHECK (
            evidence_type IN (
                'FILE_EVENT',
                'PROTECTED_FILE',
                'HONEYTOKEN',
                'CANARY_FILE',
                'FILE_COPY',
                'LOG',
                'SCREENSHOT',
                'MEMORY_DUMP',
                'PROCESS_INFORMATION',
                'SYSTEM_ARTIFACT',
                'MEDIA',
                'REPORT',
                'OTHER'
            )
        ),

    CONSTRAINT chk_incident_evidence_file_size
        CHECK (
            file_size_bytes IS NULL
            OR file_size_bytes >= 0
        ),

    CONSTRAINT chk_incident_evidence_hash_algorithm
        CHECK (
            hash_algorithm IN (
                'SHA256',
                'SHA384',
                'SHA512'
            )
        ),

    CONSTRAINT chk_incident_evidence_integrity_status
        CHECK (
            integrity_status IN (
                'PENDING',
                'VERIFIED',
                'MISMATCH',
                'UNAVAILABLE'
            )
        ),

    CONSTRAINT fk_incident_evidence_incident
        FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_incident_evidence_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_incident_evidence_threat
        FOREIGN KEY (threat_id)
        REFERENCES threats(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_incident_evidence_file_event
        FOREIGN KEY (file_event_id)
        REFERENCES file_events(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_incident_evidence_protected_file
        FOREIGN KEY (protected_file_id)
        REFERENCES protected_files(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_incident_evidence_honeytoken
        FOREIGN KEY (honeytoken_id)
        REFERENCES honeytokens(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_incident_evidence_canary_file
        FOREIGN KEY (canary_file_id)
        REFERENCES canary_files(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_incident_evidence_collected_by
        FOREIGN KEY (collected_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_incident_evidence_verified_by
        FOREIGN KEY (verified_by)
        REFERENCES users(id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_incident_threats_incident
    ON incident_threats (incident_id);

CREATE INDEX IF NOT EXISTS idx_incident_threats_threat
    ON incident_threats (threat_id);

CREATE INDEX IF NOT EXISTS idx_incident_timeline_incident
    ON incident_timeline (incident_id);

CREATE INDEX IF NOT EXISTS idx_incident_timeline_organization
    ON incident_timeline (organization_id);

CREATE INDEX IF NOT EXISTS idx_incident_timeline_event_type
    ON incident_timeline (event_type);

CREATE INDEX IF NOT EXISTS idx_incident_timeline_occurred_at
    ON incident_timeline (occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident
    ON incident_evidence (incident_id);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_organization
    ON incident_evidence (organization_id);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_threat
    ON incident_evidence (threat_id);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_file_event
    ON incident_evidence (file_event_id);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_type
    ON incident_evidence (evidence_type);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_integrity
    ON incident_evidence (integrity_status);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_collected_at
    ON incident_evidence (collected_at DESC);

COMMIT;


SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
      'incident_threats',
      'incident_timeline',
      'incident_evidence'
  )
ORDER BY table_name;