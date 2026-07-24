BEGIN;

-- Stores one security or system notification.
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    notification_sequence BIGSERIAL NOT NULL,
    notification_code VARCHAR(100) NOT NULL,

    organization_id UUID NOT NULL,
    department_id UUID NULL,

    incident_id UUID NULL,
    threat_id UUID NULL,

    notification_type VARCHAR(50) NOT NULL,
    category VARCHAR(30) NOT NULL DEFAULT 'SECURITY',

    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,

    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    priority_level INTEGER NOT NULL DEFAULT 50,

    deduplication_key VARCHAR(128) NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,

    requires_acknowledgement BOOLEAN NOT NULL DEFAULT false,
    acknowledged_by UUID NULL,
    acknowledged_at TIMESTAMP WITHOUT TIME ZONE NULL,

    status VARCHAR(30) NOT NULL DEFAULT 'CREATED',

    created_by UUID NULL,
    scheduled_at TIMESTAMP WITHOUT TIME ZONE NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE NULL,

    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITHOUT TIME ZONE NULL,

    CONSTRAINT uq_notification_sequence
        UNIQUE (notification_sequence),

    CONSTRAINT uq_notification_code
        UNIQUE (organization_id, notification_code),

    CONSTRAINT uq_notification_deduplication
        UNIQUE (organization_id, deduplication_key),

    CONSTRAINT chk_notification_type
        CHECK (
            notification_type IN (
                'THREAT_DETECTED',
                'INCIDENT_CREATED',
                'INCIDENT_ASSIGNED',
                'INCIDENT_STATUS_CHANGED',
                'EVIDENCE_MISMATCH',
                'SYSTEM_ALERT',
                'CUSTOM'
            )
        ),

    CONSTRAINT chk_notification_category
        CHECK (
            category IN (
                'SECURITY',
                'INCIDENT',
                'SYSTEM',
                'COMPLIANCE'
            )
        ),

    CONSTRAINT chk_notification_severity
        CHECK (
            severity IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    CONSTRAINT chk_notification_priority
        CHECK (
            priority_level BETWEEN 1 AND 100
        ),

    CONSTRAINT chk_notification_status
        CHECK (
            status IN (
                'CREATED',
                'QUEUED',
                'PARTIALLY_SENT',
                'SENT',
                'FAILED',
                'CANCELLED',
                'EXPIRED'
            )
        ),

    CONSTRAINT chk_notification_expiry
        CHECK (
            expires_at IS NULL
            OR expires_at > created_at
        ),

    CONSTRAINT fk_notification_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_notification_department
        FOREIGN KEY (department_id)
        REFERENCES departments(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_notification_incident
        FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_notification_threat
        FOREIGN KEY (threat_id)
        REFERENCES threats(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_notification_acknowledged_by
        FOREIGN KEY (acknowledged_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_notification_created_by
        FOREIGN KEY (created_by)
        REFERENCES users(id)
        ON DELETE SET NULL
);

-- Stores every user or external recipient selected for a notification.
CREATE TABLE IF NOT EXISTS notification_recipients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    notification_id UUID NOT NULL,
    organization_id UUID NOT NULL,

    recipient_type VARCHAR(30) NOT NULL DEFAULT 'USER',
    user_id UUID NULL,

    recipient_name VARCHAR(255) NULL,
    email_address VARCHAR(320) NULL,
    phone_number VARCHAR(30) NULL,

    in_app_status VARCHAR(30) NOT NULL DEFAULT 'UNREAD',
    read_at TIMESTAMP WITHOUT TIME ZONE NULL,
    acknowledged_at TIMESTAMP WITHOUT TIME ZONE NULL,
    dismissed_at TIMESTAMP WITHOUT TIME ZONE NULL,

    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_notification_recipient_user
        UNIQUE (notification_id, user_id),

    CONSTRAINT chk_notification_recipient_type
        CHECK (
            recipient_type IN (
                'USER',
                'EXTERNAL'
            )
        ),

    CONSTRAINT chk_notification_recipient_identity
        CHECK (
            user_id IS NOT NULL
            OR email_address IS NOT NULL
            OR phone_number IS NOT NULL
        ),

    CONSTRAINT chk_notification_in_app_status
        CHECK (
            in_app_status IN (
                'UNREAD',
                'READ',
                'ACKNOWLEDGED',
                'DISMISSED'
            )
        ),

    CONSTRAINT fk_notification_recipient_notification
        FOREIGN KEY (notification_id)
        REFERENCES notifications(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_notification_recipient_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_notification_recipient_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- Stores one delivery attempt per recipient and communication channel.
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    notification_id UUID NOT NULL,
    recipient_id UUID NOT NULL,
    organization_id UUID NOT NULL,

    channel VARCHAR(30) NOT NULL,
    delivery_status VARCHAR(30) NOT NULL DEFAULT 'QUEUED',

    attempt_count INTEGER NOT NULL DEFAULT 0,
    maximum_attempts INTEGER NOT NULL DEFAULT 5,

    provider_name VARCHAR(100) NULL,
    provider_message_id VARCHAR(255) NULL,

    last_error TEXT NULL,
    provider_response JSONB NOT NULL DEFAULT '{}'::jsonb,

    scheduled_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    next_retry_at TIMESTAMP WITHOUT TIME ZONE NULL,
    processing_started_at TIMESTAMP WITHOUT TIME ZONE NULL,
    sent_at TIMESTAMP WITHOUT TIME ZONE NULL,
    delivered_at TIMESTAMP WITHOUT TIME ZONE NULL,
    failed_at TIMESTAMP WITHOUT TIME ZONE NULL,

    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_notification_recipient_channel
        UNIQUE (
            notification_id,
            recipient_id,
            channel
        ),

    CONSTRAINT chk_notification_channel
        CHECK (
            channel IN (
                'IN_APP',
                'LOCAL_DESKTOP',
                'EMAIL',
                'SMS',
                'WEBHOOK'
            )
        ),

    CONSTRAINT chk_notification_delivery_status
        CHECK (
            delivery_status IN (
                'QUEUED',
                'PROCESSING',
                'SENT',
                'DELIVERED',
                'FAILED',
                'RETRY_SCHEDULED',
                'CANCELLED',
                'SKIPPED'
            )
        ),

    CONSTRAINT chk_notification_attempt_count
        CHECK (
            attempt_count >= 0
        ),

    CONSTRAINT chk_notification_maximum_attempts
        CHECK (
            maximum_attempts BETWEEN 1 AND 20
        ),

    CONSTRAINT fk_notification_delivery_notification
        FOREIGN KEY (notification_id)
        REFERENCES notifications(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_notification_delivery_recipient
        FOREIGN KEY (recipient_id)
        REFERENCES notification_recipients(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_notification_delivery_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notifications_organization
    ON notifications (organization_id);

CREATE INDEX IF NOT EXISTS idx_notifications_department
    ON notifications (department_id);

CREATE INDEX IF NOT EXISTS idx_notifications_incident
    ON notifications (incident_id);

CREATE INDEX IF NOT EXISTS idx_notifications_threat
    ON notifications (threat_id);

CREATE INDEX IF NOT EXISTS idx_notifications_type
    ON notifications (notification_type);

CREATE INDEX IF NOT EXISTS idx_notifications_severity
    ON notifications (severity);

CREATE INDEX IF NOT EXISTS idx_notifications_status
    ON notifications (status);

CREATE INDEX IF NOT EXISTS idx_notifications_created_at
    ON notifications (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_notification_recipients_notification
    ON notification_recipients (notification_id);

CREATE INDEX IF NOT EXISTS idx_notification_recipients_user
    ON notification_recipients (user_id);

CREATE INDEX IF NOT EXISTS idx_notification_recipients_unread
    ON notification_recipients (
        organization_id,
        user_id,
        in_app_status
    );

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_notification
    ON notification_deliveries (notification_id);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_recipient
    ON notification_deliveries (recipient_id);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_queue
    ON notification_deliveries (
        delivery_status,
        scheduled_at,
        next_retry_at
    );

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_channel
    ON notification_deliveries (channel);

COMMIT;


SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
      'notifications',
      'notification_recipients',
      'notification_deliveries'
  )
ORDER BY table_name;