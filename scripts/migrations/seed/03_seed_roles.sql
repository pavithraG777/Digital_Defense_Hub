-- ============================================================
-- FILE NAME : 03_seed_roles.sql
-- PURPOSE   : Insert initial roles for the platform
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
-- Insert initial organization roles
-- ------------------------------------------------------------

WITH organization_record AS (
    SELECT id AS organization_id
    FROM organizations
    WHERE organization_code = 'CSL001'
      AND deleted_at IS NULL
    LIMIT 1
),
role_seed AS (
    SELECT *
    FROM (
        VALUES

        (
            'SUPER_ADMIN',
            'Super Administrator',
            'Has complete access to all organizations, users, roles, permissions, security modules and system settings.',
            TRUE,
            1
        ),

        (
            'ORG_ADMIN',
            'Organization Administrator',
            'Manages organization users, departments, roles, reports and organization-level platform settings.',
            TRUE,
            10
        ),

        (
            'SOC_ANALYST',
            'SOC Analyst',
            'Monitors security alerts, honeytokens, canary files, incidents and suspicious activities.',
            TRUE,
            20
        ),

        (
            'FORENSIC_ANALYST',
            'Digital Forensic Analyst',
            'Collects, preserves, verifies and analyzes digital evidence and forensic investigation records.',
            TRUE,
            30
        ),

        (
            'INCIDENT_RESPONDER',
            'Incident Responder',
            'Handles cyber incident investigation, containment, recovery and incident resolution activities.',
            TRUE,
            40
        ),

        (
            'THREAT_ANALYST',
            'Threat Intelligence Analyst',
            'Manages indicators of compromise, threat intelligence data and cyber threat analysis.',
            TRUE,
            50
        ),

        (
            'AI_ANALYST',
            'AI Forensic Analyst',
            'Runs offline AI models for deepfake detection, media analysis and forensic classification.',
            TRUE,
            60
        ),

        (
            'INVESTIGATOR',
            'Investigator',
            'Reviews incidents, evidence, analysis results and investigation reports.',
            TRUE,
            70
        ),

        (
            'AUDITOR',
            'Security Auditor',
            'Reviews audit logs, access history, security reports and compliance information.',
            TRUE,
            80
        ),

        (
            'VIEWER',
            'Read Only Viewer',
            'Can view permitted dashboard, alert, incident and report information without modifying records.',
            TRUE,
            100
        )

    ) AS roles_data (
        role_code,
        role_name,
        description,
        is_system_role,
        priority_level
    )
)

INSERT INTO roles (
    organization_id,
    role_code,
    role_name,
    description,
    role_scope,
    department_id,
    is_system_role,
    priority_level,
    status
)
SELECT
    organization_record.organization_id,
    role_seed.role_code,
    role_seed.role_name,
    role_seed.description,
    'ORGANIZATION',
    NULL,
    role_seed.is_system_role,
    role_seed.priority_level,
    'ACTIVE'
FROM role_seed
CROSS JOIN organization_record
WHERE NOT EXISTS (
    SELECT 1
    FROM roles existing_role
    WHERE existing_role.organization_id =
          organization_record.organization_id
      AND existing_role.role_code =
          role_seed.role_code
      AND existing_role.deleted_at IS NULL
);

COMMIT;

-- ------------------------------------------------------------
-- Verification
-- ------------------------------------------------------------

SELECT
    r.id,
    o.organization_code,
    r.role_code,
    r.role_name,
    r.role_scope,
    r.is_system_role,
    r.priority_level,
    r.status
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
WHERE o.organization_code = 'CSL001'
  AND r.deleted_at IS NULL
ORDER BY r.priority_level;