-- ============================================================
-- FILE NAME : 07_seed_user_profiles.sql
-- PURPOSE   : Create default Super Admin profile
-- PROJECT   : Offline-First Cyber Security and
--             Digital Forensics Platform
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- Verify Super Admin user exists
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM users
        WHERE username = 'superadmin'
          AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'Super Admin user does not exist. Run 06_seed_admin_user.sql first.';
    END IF;
END;
$$;

-- ------------------------------------------------------------
-- Insert Super Admin Profile
-- ------------------------------------------------------------

INSERT INTO user_profiles (
    id,
    user_id,
    employee_code,
    first_name,
    middle_name,
    last_name,
    display_name,
    designation,
    employment_type,
    date_of_joining,
    date_of_birth,
    gender,
    official_phone,
    alternate_phone,
    profile_photo_path,
    address_line1,
    address_line2,
    city,
    district,
    state,
    postal_code,
    country,
    emergency_contact_name,
    emergency_contact_relationship,
    emergency_contact_phone,
    security_clearance_level,
    notes,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    u.id,
    'EMP0001',
    'System',
    NULL,
    'Administrator',
    'System Administrator',
    'Chief Security Administrator',
    'PERMANENT',
    CURRENT_DATE,
    NULL,
    'PREFER_NOT_TO_SAY',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    'Coimbatore',
    'Coimbatore',
    'Tamil Nadu',
    '641001',
    'India',
    NULL,
    NULL,
    NULL,
    'HIGHLY_RESTRICTED',
    'Default Super Administrator Account',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM users u
WHERE u.username = 'superadmin'
  AND u.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM user_profiles up
      WHERE up.user_id = u.id
  );

COMMIT;

-- ============================================================
-- VERIFICATION
-- ============================================================

SELECT
    u.username,
    up.employee_code,
    up.display_name,
    up.designation,
    up.employment_type,
    up.security_clearance_level
FROM user_profiles up
JOIN users u
    ON u.id = up.user_id
WHERE u.username = 'superadmin';