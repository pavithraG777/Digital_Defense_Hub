-- ============================================================
-- FILE NAME : 08_seed_user_roles.sql
-- PURPOSE   : Assign SUPER_ADMIN role to default admin user
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
        FROM users u
        JOIN organizations o
            ON o.id = u.organization_id
        WHERE o.organization_code = 'CSL001'
          AND u.username = 'superadmin'
          AND u.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'Super Admin user does not exist. Run 06_seed_admin_user.sql first.';
    END IF;
END;
$$;

-- ------------------------------------------------------------
-- Verify SUPER_ADMIN role exists
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM roles r
        JOIN organizations o
            ON o.id = r.organization_id
        WHERE o.organization_code = 'CSL001'
          AND r.role_code = 'SUPER_ADMIN'
          AND r.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'SUPER_ADMIN role does not exist. Run 03_seed_roles.sql first.';
    END IF;
END;
$$;

-- ------------------------------------------------------------
-- Assign SUPER_ADMIN role to the default admin
-- ------------------------------------------------------------

INSERT INTO user_roles (
    id,
    user_id,
    role_id,
    assigned_by,
    assignment_reason,
    assigned_at,
    valid_from,
    valid_until,
    is_primary,
    status,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    u.id,
    r.id,
    NULL,
    'Default SUPER_ADMIN role assigned during system installation',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE,
    'ACTIVE',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
JOIN roles r
    ON r.organization_id = o.id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
  AND r.role_code = 'SUPER_ADMIN'
  AND r.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM user_roles ur
      WHERE ur.user_id = u.id
        AND ur.role_id = r.id
        AND ur.status = 'ACTIVE'
  );

COMMIT;

-- ============================================================
-- VERIFICATION
-- ============================================================

SELECT
    u.username,
    u.official_email,
    r.role_code,
    r.role_name,
    ur.assignment_reason,
    ur.assigned_at,
    ur.valid_from,
    ur.valid_until,
    ur.is_primary,
    ur.status
FROM user_roles ur
JOIN users u
    ON u.id = ur.user_id
JOIN roles r
    ON r.id = ur.role_id
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND r.role_code = 'SUPER_ADMIN';