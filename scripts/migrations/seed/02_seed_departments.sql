-- ============================================================
-- FILE NAME : 02_seed_departments.sql
-- PURPOSE   : Insert initial departments for Cyber Security Lab
-- PROJECT   : Offline-First Cyber Security and
--             Digital Forensics Platform
-- ============================================================

BEGIN;

-- ------------------------------------------------------------
-- Verify that the parent organization exists
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
-- Insert the initial departments
-- ------------------------------------------------------------

WITH organization_record AS (
    SELECT id AS organization_id
    FROM organizations
    WHERE organization_code = 'CSL001'
      AND deleted_at IS NULL
    LIMIT 1
),
department_seed AS (
    SELECT *
    FROM (
        VALUES

        (
            'ADMIN',
            'Administration',
            'Administration',
            'ADMINISTRATION',
            'Handles organization administration, user management, roles, permissions and platform configuration.',
            'admin@cyberlab.local',
            'Coimbatore, Tamil Nadu',
            'CONFIDENTIAL',
            TRUE,
            FALSE,
            FALSE,
            TRUE
        ),

        (
            'SOC',
            'Security Operations Center',
            'SOC',
            'SECURITY_OPERATIONS',
            'Monitors security events, honeytokens, canary files, alerts and cyber security incidents.',
            'soc@cyberlab.local',
            'Coimbatore, Tamil Nadu',
            'RESTRICTED',
            TRUE,
            TRUE,
            FALSE,
            TRUE
        ),

        (
            'DFL',
            'Digital Forensics Laboratory',
            'Digital Forensics',
            'DIGITAL_FORENSICS',
            'Collects, preserves, verifies and analyzes digital evidence while maintaining chain of custody.',
            'forensics@cyberlab.local',
            'Coimbatore, Tamil Nadu',
            'RESTRICTED',
            TRUE,
            TRUE,
            TRUE,
            TRUE
        ),

        (
            'AIR',
            'Artificial Intelligence Research',
            'AI Research',
            'AI_RESEARCH',
            'Develops and manages offline AI models for deepfake detection, media forensics, OCR and risk analysis.',
            'ai-research@cyberlab.local',
            'Coimbatore, Tamil Nadu',
            'CONFIDENTIAL',
            TRUE,
            FALSE,
            TRUE,
            TRUE
        ),

        (
            'IR',
            'Incident Response',
            'Incident Response',
            'INCIDENT_RESPONSE',
            'Investigates cyber security incidents and performs containment, recovery and response activities.',
            'incident-response@cyberlab.local',
            'Coimbatore, Tamil Nadu',
            'RESTRICTED',
            TRUE,
            TRUE,
            FALSE,
            TRUE
        ),

        (
            'TI',
            'Threat Intelligence',
            'Threat Intelligence',
            'THREAT_INTELLIGENCE',
            'Maintains offline threat intelligence, indicators of compromise and ransomware information.',
            'threat-intelligence@cyberlab.local',
            'Coimbatore, Tamil Nadu',
            'CONFIDENTIAL',
            TRUE,
            TRUE,
            FALSE,
            TRUE
        )

    ) AS departments_data (
        department_code,
        department_name,
        display_name,
        department_type,
        description,
        email,
        location,
        security_level,
        handles_sensitive_data,
        honeytoken_enabled,
        deepfake_analysis_enabled,
        evidence_access_enabled
    )
)

INSERT INTO departments (
    organization_id,
    parent_department_id,
    department_code,
    department_name,
    display_name,
    department_type,
    description,
    email,
    phone,
    location,
    security_level,
    handles_sensitive_data,
    honeytoken_enabled,
    deepfake_analysis_enabled,
    evidence_access_enabled,
    status
)
SELECT
    organization_record.organization_id,
    NULL,
    department_seed.department_code,
    department_seed.department_name,
    department_seed.display_name,
    department_seed.department_type,
    department_seed.description,
    department_seed.email,
    NULL,
    department_seed.location,
    department_seed.security_level,
    department_seed.handles_sensitive_data,
    department_seed.honeytoken_enabled,
    department_seed.deepfake_analysis_enabled,
    department_seed.evidence_access_enabled,
    'ACTIVE'
FROM department_seed
CROSS JOIN organization_record
WHERE NOT EXISTS (
    SELECT 1
    FROM departments existing_department
    WHERE existing_department.organization_id =
          organization_record.organization_id
      AND existing_department.department_code =
          department_seed.department_code
);

COMMIT;

-- ------------------------------------------------------------
-- Verification
-- ------------------------------------------------------------

SELECT
    d.id,
    o.organization_code,
    d.department_code,
    d.department_name,
    d.department_type,
    d.security_level,
    d.handles_sensitive_data,
    d.honeytoken_enabled,
    d.deepfake_analysis_enabled,
    d.evidence_access_enabled,
    d.status
FROM departments d
JOIN organizations o
    ON o.id = d.organization_id
WHERE o.organization_code = 'CSL001'
ORDER BY d.department_code;