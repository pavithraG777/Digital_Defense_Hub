-- ============================================================
-- FILE NAME : 06_seed_admin_user.sql
-- PURPOSE   : Create the default Super Admin user
-- PROJECT   : Offline-First Cyber Security and
--             Digital Forensics Platform
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- Verify organization exists
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM organizations
        WHERE organization_code = 'CSL001'
          AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'Organization CSL001 does not exist. Run 01_seed_organization.sql first.';
    END IF;
END;
$$;

-- ------------------------------------------------------------
-- Insert default Super Admin user
-- ------------------------------------------------------------

INSERT INTO users (
    id,
    organization_id,
    username,
    official_email,
    password_hash,
    user_type,
    account_status,
    email_verified,
    phone_verified,
    mfa_enabled,
    must_change_password,
    failed_login_attempts,
    locked_until,
    password_changed_at,
    last_login_at,
    last_logout_at,
    preferred_language,
    timezone,
    created_at,
    updated_at,
    deleted_at
)
SELECT
    gen_random_uuid(),
    o.id,
    'superadmin',
    'admin@csl.local',

        -- Before running this script, configure a valid bcrypt hash
    -- in the same PostgreSQL session:
    -- SET app.bootstrap_admin_password_hash = '<BCRYPT_HASH>';

    NULLIF(
        current_setting(
            'app.bootstrap_admin_password_hash',
            TRUE
        ),
        ''
    ),

    'INTERNAL',
    'ACTIVE',
    TRUE,
    FALSE,
    FALSE,
    TRUE,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    'en',
    'Asia/Kolkata',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    NULL
FROM organizations o
WHERE o.organization_code = 'CSL001'
  AND o.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM users u
      WHERE u.organization_id = o.id
        AND (
            LOWER(u.username) = LOWER('superadmin')
            OR LOWER(u.official_email) = LOWER('admin@csl.local')
        )
        AND u.deleted_at IS NULL
  );

COMMIT;

-- ============================================================
-- VERIFICATION
-- ============================================================

SELECT
    u.id,
    o.organization_code,
    u.username,
    u.official_email,
    u.user_type,
    u.account_status,
    u.email_verified,
    u.phone_verified,
    u.mfa_enabled,
    u.must_change_password,
    u.failed_login_attempts,
    u.preferred_language,
    u.timezone,
    u.created_at
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL;