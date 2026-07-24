-- ============================================================
-- FILE NAME : 10_seed_system_settings.sql
-- PURPOSE   : Insert default application-level system settings
-- PROJECT   : Offline-First Cyber Security and
--             Digital Forensics Platform
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- Verify default Super Admin exists
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM users u
        JOIN organizations o
            ON o.id = u.organization_id
        WHERE o.organization_code = 'CSL001'
          AND u.username = 'superadmin'
          AND u.account_status = 'ACTIVE'
          AND u.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'Active Super Admin user does not exist. Run 06_seed_admin_user.sql first.';
    END IF;
END;
$$;

-- ============================================================
-- GENERAL SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    validation_pattern,
    allowed_values,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'APPLICATION_NAME',
    'Application Name',
    'Display name of the cyber security and digital forensics platform.',
    'GENERAL',
    'STRING',
    'Cyber Security and Digital Forensics Platform',
    'Cyber Security and Digital Forensics Platform',
    NULL,
    NULL,
    '^.{3,150}$',
    NULL,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    allowed_values,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'DEPLOYMENT_MODE',
    'Deployment Mode',
    'Defines whether the application operates in offline, online, or hybrid mode.',
    'GENERAL',
    'STRING',
    'OFFLINE',
    'OFFLINE',
    '["OFFLINE", "ONLINE", "HYBRID"]'::jsonb,
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    FALSE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    validation_pattern,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'DEFAULT_TIMEZONE',
    'Default Timezone',
    'Default timezone used for displaying application dates and times.',
    'GENERAL',
    'STRING',
    'Asia/Kolkata',
    'Asia/Kolkata',
    '^[A-Za-z_]+/[A-Za-z_]+$',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    allowed_values,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'DEFAULT_LANGUAGE',
    'Default Language',
    'Default language used by the application interface.',
    'GENERAL',
    'STRING',
    'en',
    'en',
    '["en", "ta"]'::jsonb,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- AUTHENTICATION SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'MFA_ENABLED',
    'Multi-Factor Authentication',
    'Enables or disables multi-factor authentication support.',
    'AUTHENTICATION',
    'BOOLEAN',
    'false',
    'false',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'MAX_FAILED_LOGIN_ATTEMPTS',
    'Maximum Failed Login Attempts',
    'Maximum number of failed login attempts allowed before account lockout.',
    'AUTHENTICATION',
    'INTEGER',
    '5',
    '5',
    1,
    20,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'ACCOUNT_LOCKOUT_DURATION_MINUTES',
    'Account Lockout Duration',
    'Number of minutes a user account remains locked after repeated failed login attempts.',
    'AUTHENTICATION',
    'INTEGER',
    '30',
    '30',
    1,
    1440,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- PASSWORD SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'PASSWORD_MINIMUM_LENGTH',
    'Minimum Password Length',
    'Minimum number of characters required for a user password.',
    'PASSWORD',
    'INTEGER',
    '8',
    '8',
    8,
    64,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'PASSWORD_REQUIRE_UPPERCASE',
    'Require Uppercase Character',
    'Requires at least one uppercase English letter in passwords.',
    'PASSWORD',
    'BOOLEAN',
    'true',
    'true',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'PASSWORD_REQUIRE_LOWERCASE',
    'Require Lowercase Character',
    'Requires at least one lowercase English letter in passwords.',
    'PASSWORD',
    'BOOLEAN',
    'true',
    'true',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'PASSWORD_REQUIRE_NUMBER',
    'Require Numeric Character',
    'Requires at least one numeric character in passwords.',
    'PASSWORD',
    'BOOLEAN',
    'true',
    'true',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'PASSWORD_REQUIRE_SPECIAL_CHARACTER',
    'Require Special Character',
    'Requires at least one special character in passwords.',
    'PASSWORD',
    'BOOLEAN',
    'true',
    'true',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'PASSWORD_EXPIRY_DAYS',
    'Password Expiry Period',
    'Number of days after which a user password must be changed. Zero disables expiry.',
    'PASSWORD',
    'INTEGER',
    '90',
    '90',
    0,
    365,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- SESSION SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'SESSION_TIMEOUT_MINUTES',
    'Session Timeout',
    'Automatically ends an inactive user session after the configured number of minutes.',
    'SESSION',
    'INTEGER',
    '30',
    '30',
    5,
    1440,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'MAX_CONCURRENT_SESSIONS',
    'Maximum Concurrent Sessions',
    'Maximum number of active sessions allowed for a single user account.',
    'SESSION',
    'INTEGER',
    '3',
    '3',
    1,
    10,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- EVIDENCE SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    validation_pattern,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'EVIDENCE_STORAGE_PATH',
    'Evidence Storage Path',
    'Local directory used for storing uploaded digital evidence files.',
    'EVIDENCE',
    'PATH',
    './storage/evidence',
    './storage/evidence',
    '^.{1,500}$',
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    allowed_values,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'EVIDENCE_HASH_ALGORITHM',
    'Evidence Hash Algorithm',
    'Hashing algorithm used to verify the integrity of digital evidence.',
    'EVIDENCE',
    'STRING',
    'SHA-256',
    'SHA-256',
    '["SHA-256", "SHA-384", "SHA-512"]'::jsonb,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'MAX_EVIDENCE_FILE_SIZE_MB',
    'Maximum Evidence File Size',
    'Maximum permitted size of an individual digital evidence file in megabytes.',
    'EVIDENCE',
    'INTEGER',
    '2048',
    '2048',
    1,
    10240,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'EVIDENCE_ENCRYPTION_ENABLED',
    'Evidence Encryption',
    'Enables encryption for stored digital evidence files.',
    'EVIDENCE',
    'BOOLEAN',
    'true',
    'true',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- AI ANALYSIS SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'AI_CONFIDENCE_THRESHOLD',
    'AI Confidence Threshold',
    'Minimum confidence score required for an AI analysis result to be treated as reliable.',
    'AI_ANALYSIS',
    'DECIMAL',
    '0.75',
    '0.75',
    0,
    1,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'AI_MAX_CONCURRENT_JOBS',
    'Maximum Concurrent AI Jobs',
    'Maximum number of AI analysis jobs that can run simultaneously.',
    'AI_ANALYSIS',
    'INTEGER',
    '2',
    '2',
    1,
    16,
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'AI_OFFLINE_PROCESSING_ENABLED',
    'Offline AI Processing',
    'Allows AI models to perform analysis without an internet connection.',
    'AI_ANALYSIS',
    'BOOLEAN',
    'true',
    'true',
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    FALSE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- ALERT AND INCIDENT SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    allowed_values,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'DEFAULT_ALERT_SEVERITY',
    'Default Alert Severity',
    'Default severity assigned to an alert when no severity is provided.',
    'ALERT',
    'STRING',
    'MEDIUM',
    'MEDIUM',
    '["LOW", "MEDIUM", "HIGH", "CRITICAL"]'::jsonb,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'AUTO_CREATE_INCIDENT_FOR_CRITICAL_ALERT',
    'Auto-Create Incident for Critical Alert',
    'Automatically creates an incident when a critical security alert is generated.',
    'INCIDENT',
    'BOOLEAN',
    'true',
    'true',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- REPORT AND DASHBOARD SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    allowed_values,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'DEFAULT_REPORT_FORMAT',
    'Default Report Format',
    'Default output format used when generating reports.',
    'REPORT',
    'STRING',
    'PDF',
    'PDF',
    '["PDF", "CSV", "XLSX", "JSON"]'::jsonb,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'DASHBOARD_REFRESH_INTERVAL_SECONDS',
    'Dashboard Refresh Interval',
    'Time interval in seconds between automatic dashboard data refreshes.',
    'DASHBOARD',
    'INTEGER',
    '30',
    '30',
    5,
    3600,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- STORAGE AND BACKUP SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    validation_pattern,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'APPLICATION_STORAGE_PATH',
    'Application Storage Path',
    'Base local storage directory used by the application.',
    'STORAGE',
    'PATH',
    './storage',
    './storage',
    '^.{1,500}$',
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    validation_pattern,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'BACKUP_STORAGE_PATH',
    'Backup Storage Path',
    'Local directory used to store database and application backup files.',
    'BACKUP',
    'PATH',
    './storage/backups',
    './storage/backups',
    '^.{1,500}$',
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'BACKUP_RETENTION_DAYS',
    'Backup Retention Period',
    'Number of days application backup files are retained.',
    'BACKUP',
    'INTEGER',
    '30',
    '30',
    1,
    3650,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'AUTOMATIC_BACKUP_ENABLED',
    'Automatic Backup',
    'Enables automatic scheduled backup of application data.',
    'BACKUP',
    'BOOLEAN',
    'true',
    'true',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- LOGGING AND AUDIT SETTINGS
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    allowed_values,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'APPLICATION_LOG_LEVEL',
    'Application Log Level',
    'Minimum application event severity recorded in log files.',
    'LOGGING',
    'STRING',
    'INFO',
    'INFO',
    '["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]'::jsonb,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    minimum_value,
    maximum_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'AUDIT_LOG_RETENTION_DAYS',
    'Audit Log Retention Period',
    'Number of days audit records are retained before archival.',
    'AUDIT',
    'INTEGER',
    '365',
    '365',
    30,
    3650,
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'AUDIT_USER_ACTIONS_ENABLED',
    'User Action Auditing',
    'Records important user actions in the audit log.',
    'AUDIT',
    'BOOLEAN',
    'true',
    'true',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


-- ============================================================
-- MAINTENANCE SETTING
-- ============================================================

INSERT INTO system_settings (
    setting_key,
    setting_name,
    description,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    is_sensitive,
    is_encrypted,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status,
    created_by,
    updated_by
)
SELECT
    'MAINTENANCE_MODE_ENABLED',
    'Maintenance Mode',
    'Temporarily prevents normal users from accessing the application during maintenance.',
    'MAINTENANCE',
    'BOOLEAN',
    'false',
    'false',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    'ACTIVE',
    u.id,
    u.id
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (setting_key) DO NOTHING;


COMMIT;

-- ============================================================
-- VERIFICATION
-- ============================================================

SELECT
    setting_key,
    setting_name,
    setting_category,
    value_type,
    setting_value,
    default_value,
    is_required,
    requires_restart,
    allow_organization_override,
    is_user_visible,
    status
FROM system_settings
WHERE deleted_at IS NULL
ORDER BY
    setting_category,
    setting_key;


-- ============================================================
-- COUNT VERIFICATION
-- ============================================================

SELECT
    setting_category,
    COUNT(*) AS total_settings
FROM system_settings
WHERE deleted_at IS NULL
GROUP BY setting_category
ORDER BY setting_category;