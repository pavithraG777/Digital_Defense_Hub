-- ============================================================
-- FILE NAME : 999_seed_test_user.sql
-- PURPOSE   : Create a test user for authentication testing
-- ============================================================

BEGIN;

-- Insert test user
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
    'testuser',
    'testuser@cyberlab.local',
    '$2a$10$JQLaXP..MXYTku9eAB7tRehgMihk2PoTDINQ1jx.vaajj2yk22F3e',  -- Test1234!@#
    'INTERNAL',
    'ACTIVE',
    TRUE,
    FALSE,
    FALSE,
    FALSE,  -- Don't force password change for test user
    0,
    NULL,
    NOW(),
    NULL,
    NULL,
    'en',
    'Asia/Kolkata',
    NOW(),
    NOW(),
    NULL
FROM organizations o
WHERE o.organization_code = 'CSL001'
  AND o.deleted_at IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM users u
    WHERE u.username = 'testuser'
      AND u.organization_id = o.id
      AND u.deleted_at IS NULL
  );

COMMIT;
