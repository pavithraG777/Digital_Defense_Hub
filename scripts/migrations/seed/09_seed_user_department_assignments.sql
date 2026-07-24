-- ============================================================
-- FILE NAME : 09_seed_user_department_assignments.sql
-- PURPOSE   : Assign the default Super Admin user to the
--             Administration department
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
-- Verify ADMIN department exists
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM departments d
        JOIN organizations o
            ON o.id = d.organization_id
        WHERE o.organization_code = 'CSL001'
          AND d.department_code = 'ADMIN'
          AND d.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'ADMIN department does not exist. Run 02_seed_departments.sql first.';
    END IF;
END;
$$;

-- ------------------------------------------------------------
-- Assign Super Admin to ADMIN department
-- ------------------------------------------------------------

INSERT INTO user_department_assignments (
    id,
    user_id,
    department_id,
    assignment_type,
    job_title,
    is_department_admin,
    assignment_start_date,
    assignment_end_date,
    status,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    u.id,
    d.id,
    'PRIMARY',
    'Chief Security Administrator',
    TRUE,
    CURRENT_DATE,
    NULL,
    'ACTIVE',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM users u
JOIN organizations o
    ON o.id = u.organization_id
JOIN departments d
    ON d.organization_id = o.id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
  AND d.department_code = 'ADMIN'
  AND d.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM user_department_assignments uda
      WHERE uda.user_id = u.id
        AND uda.department_id = d.id
        AND uda.status = 'ACTIVE'
  );

COMMIT;

-- ============================================================
-- VERIFICATION
-- ============================================================

SELECT
    u.username,
    u.official_email,
    d.department_code,
    d.department_name,
    uda.assignment_type,
    uda.job_title,
    uda.is_department_admin,
    uda.assignment_start_date,
    uda.assignment_end_date,
    uda.status
FROM user_department_assignments uda
JOIN users u
    ON u.id = uda.user_id
JOIN departments d
    ON d.id = uda.department_id
JOIN organizations o
    ON o.id = u.organization_id
WHERE o.organization_code = 'CSL001'
  AND u.username = 'superadmin'
  AND d.department_code = 'ADMIN';