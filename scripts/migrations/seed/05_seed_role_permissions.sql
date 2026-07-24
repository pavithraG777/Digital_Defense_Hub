-- ============================================================
-- FILE NAME : 05_seed_role_permissions.sql
-- PURPOSE   : Assign permissions to default platform roles
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
-- Verify roles exist
-- ------------------------------------------------------------

DO $$
DECLARE
    missing_role_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO missing_role_count
    FROM (
        VALUES
            ('SUPER_ADMIN'),
            ('ORG_ADMIN'),
            ('SOC_ANALYST'),
            ('FORENSIC_ANALYST'),
            ('INCIDENT_RESPONDER'),
            ('THREAT_ANALYST'),
            ('AI_ANALYST'),
            ('INVESTIGATOR'),
            ('AUDITOR'),
            ('VIEWER')
    ) AS required_roles(role_code)
    WHERE NOT EXISTS (
        SELECT 1
        FROM roles r
        JOIN organizations o
            ON o.id = r.organization_id
        WHERE r.role_code = required_roles.role_code
          AND o.organization_code = 'CSL001'
          AND r.deleted_at IS NULL
    );

    IF missing_role_count > 0 THEN
        RAISE EXCEPTION
            'Some required roles are missing. Run 03_seed_roles.sql first.';
    END IF;
END;
$$;

-- ------------------------------------------------------------
-- Verify permissions exist
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM permissions
        WHERE status = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION
            'Permissions are missing. Run 04_seed_permissions.sql first.';
    END IF;
END;
$$;

-- ============================================================
-- 1. SUPER ADMIN
-- Assign every active permission
-- ============================================================

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permissions p
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'SUPER_ADMIN'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

-- ============================================================
-- 2. ORGANIZATION ADMIN
-- ============================================================

WITH permission_codes AS (
    SELECT permission_code
    FROM (
        VALUES
            ('DASHBOARD_VIEW'),
            ('DASHBOARD_VIEW_STATISTICS'),
            ('DASHBOARD_EXPORT'),
            ('DASHBOARD_CUSTOMIZE'),

            ('ORGANIZATION_VIEW'),
            ('ORGANIZATION_UPDATE'),
            ('ORGANIZATION_MANAGE_SECURITY'),

            ('DEPARTMENT_VIEW'),
            ('DEPARTMENT_CREATE'),
            ('DEPARTMENT_UPDATE'),
            ('DEPARTMENT_DELETE'),
            ('DEPARTMENT_ASSIGN_PARENT'),
            ('DEPARTMENT_MANAGE_SECURITY'),

            ('USER_VIEW'),
            ('USER_VIEW_DETAILS'),
            ('USER_CREATE'),
            ('USER_UPDATE'),
            ('USER_ACTIVATE'),
            ('USER_DEACTIVATE'),
            ('USER_LOCK'),
            ('USER_UNLOCK'),
            ('USER_RESET_PASSWORD'),
            ('USER_MANAGE_MFA'),
            ('USER_EXPORT'),

            ('ROLE_VIEW'),
            ('ROLE_CREATE'),
            ('ROLE_UPDATE'),
            ('ROLE_ASSIGN'),
            ('ROLE_REVOKE'),
            ('ROLE_VIEW_PERMISSIONS'),

            ('PERMISSION_VIEW'),

            ('AUTH_VIEW_SESSIONS'),
            ('AUTH_REVOKE_SESSION'),
            ('AUTH_VIEW_LOGIN_HISTORY'),

            ('REPORT_VIEW'),
            ('REPORT_CREATE'),
            ('REPORT_GENERATE'),
            ('REPORT_UPDATE'),
            ('REPORT_APPROVE'),
            ('REPORT_EXPORT'),
            ('REPORT_PRINT'),
            ('REPORT_SHARE'),

            ('REPORT_TEMPLATE_VIEW'),
            ('REPORT_TEMPLATE_CREATE'),
            ('REPORT_TEMPLATE_UPDATE'),
            ('REPORT_TEMPLATE_DELETE'),

            ('SYSTEM_SETTING_VIEW'),

            ('FEATURE_FLAG_VIEW'),

            ('AUDIT_LOG_VIEW'),

            ('BACKUP_VIEW')
    ) AS values_list(permission_code)
)

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permission_codes pc
JOIN permissions p
    ON p.permission_code = pc.permission_code
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'ORG_ADMIN'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

-- ============================================================
-- 3. SOC ANALYST
-- ============================================================

WITH permission_codes AS (
    SELECT permission_code
    FROM (
        VALUES
            ('DASHBOARD_VIEW'),
            ('DASHBOARD_VIEW_STATISTICS'),

            ('HONEYTOKEN_VIEW'),
            ('HONEYTOKEN_CREATE'),
            ('HONEYTOKEN_UPDATE'),
            ('HONEYTOKEN_DEPLOY'),
            ('HONEYTOKEN_DEACTIVATE'),
            ('HONEYTOKEN_VIEW_ACCESS_LOG'),
            ('HONEYTOKEN_VERIFY'),

            ('CANARY_FILE_VIEW'),
            ('CANARY_FILE_CREATE'),
            ('CANARY_FILE_UPDATE'),
            ('CANARY_FILE_DEPLOY'),
            ('CANARY_FILE_VERIFY'),
            ('CANARY_FILE_VIEW_EVENTS'),
            ('CANARY_FILE_REGENERATE'),

            ('ALERT_VIEW'),
            ('ALERT_VIEW_DETAILS'),
            ('ALERT_ACKNOWLEDGE'),
            ('ALERT_ASSIGN'),
            ('ALERT_UPDATE_STATUS'),
            ('ALERT_ESCALATE'),
            ('ALERT_CLOSE'),
            ('ALERT_EXPORT'),

            ('INCIDENT_VIEW'),
            ('INCIDENT_CREATE'),
            ('INCIDENT_UPDATE'),
            ('INCIDENT_ASSIGN'),
            ('INCIDENT_CHANGE_PRIORITY'),
            ('INCIDENT_ESCALATE'),
            ('INCIDENT_ADD_TIMELINE'),
            ('INCIDENT_ADD_NOTE'),

            ('REPORT_VIEW'),
            ('REPORT_CREATE'),
            ('REPORT_GENERATE'),
            ('REPORT_EXPORT'),

            ('AUDIT_LOG_VIEW')
    ) AS values_list(permission_code)
)

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permission_codes pc
JOIN permissions p
    ON p.permission_code = pc.permission_code
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'SOC_ANALYST'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

-- ============================================================
-- 4. DIGITAL FORENSIC ANALYST
-- ============================================================

WITH permission_codes AS (
    SELECT permission_code
    FROM (
        VALUES
            ('DASHBOARD_VIEW'),
            ('DASHBOARD_VIEW_STATISTICS'),

            ('ALERT_VIEW'),
            ('ALERT_VIEW_DETAILS'),

            ('INCIDENT_VIEW'),
            ('INCIDENT_CREATE'),
            ('INCIDENT_UPDATE'),
            ('INCIDENT_ADD_TIMELINE'),
            ('INCIDENT_ADD_NOTE'),

            ('EVIDENCE_VIEW'),
            ('EVIDENCE_VIEW_SENSITIVE'),
            ('EVIDENCE_UPLOAD'),
            ('EVIDENCE_UPDATE_METADATA'),
            ('EVIDENCE_VERIFY_HASH'),
            ('EVIDENCE_DOWNLOAD'),
            ('EVIDENCE_EXPORT'),
            ('EVIDENCE_ARCHIVE'),
            ('EVIDENCE_RESTORE'),
            ('EVIDENCE_ADD_CUSTODY_RECORD'),
            ('EVIDENCE_TRANSFER_CUSTODY'),
            ('EVIDENCE_VIEW_CUSTODY'),
            ('EVIDENCE_LOCK'),

            ('AI_MODEL_VIEW'),

            ('AI_ANALYSIS_VIEW'),
            ('AI_ANALYSIS_CREATE'),
            ('AI_ANALYSIS_EXECUTE'),
            ('AI_ANALYSIS_CANCEL'),
            ('AI_ANALYSIS_RETRY'),
            ('AI_ANALYSIS_REVIEW'),
            ('AI_ANALYSIS_EXPORT'),

            ('REPORT_VIEW'),
            ('REPORT_CREATE'),
            ('REPORT_GENERATE'),
            ('REPORT_EXPORT'),
            ('REPORT_PRINT'),

            ('AUDIT_LOG_VIEW')
    ) AS values_list(permission_code)
)

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permission_codes pc
JOIN permissions p
    ON p.permission_code = pc.permission_code
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'FORENSIC_ANALYST'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

-- ============================================================
-- 5. INCIDENT RESPONDER
-- ============================================================

WITH permission_codes AS (
    SELECT permission_code
    FROM (
        VALUES
            ('DASHBOARD_VIEW'),
            ('DASHBOARD_VIEW_STATISTICS'),

            ('ALERT_VIEW'),
            ('ALERT_VIEW_DETAILS'),
            ('ALERT_ACKNOWLEDGE'),
            ('ALERT_ASSIGN'),
            ('ALERT_UPDATE_STATUS'),
            ('ALERT_ESCALATE'),
            ('ALERT_CLOSE'),

            ('INCIDENT_VIEW'),
            ('INCIDENT_CREATE'),
            ('INCIDENT_UPDATE'),
            ('INCIDENT_ASSIGN'),
            ('INCIDENT_CHANGE_PRIORITY'),
            ('INCIDENT_ESCALATE'),
            ('INCIDENT_ADD_TIMELINE'),
            ('INCIDENT_ADD_NOTE'),
            ('INCIDENT_CONTAIN'),
            ('INCIDENT_RESOLVE'),
            ('INCIDENT_CLOSE'),
            ('INCIDENT_REOPEN'),
            ('INCIDENT_EXPORT'),

            ('EVIDENCE_VIEW'),
            ('EVIDENCE_UPLOAD'),
            ('EVIDENCE_UPDATE_METADATA'),
            ('EVIDENCE_VERIFY_HASH'),
            ('EVIDENCE_ADD_CUSTODY_RECORD'),
            ('EVIDENCE_VIEW_CUSTODY'),

            ('REPORT_VIEW'),
            ('REPORT_CREATE'),
            ('REPORT_GENERATE'),
            ('REPORT_EXPORT'),

            ('AUDIT_LOG_VIEW')
    ) AS values_list(permission_code)
)

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permission_codes pc
JOIN permissions p
    ON p.permission_code = pc.permission_code
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'INCIDENT_RESPONDER'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

-- ============================================================
-- 6. THREAT INTELLIGENCE ANALYST
-- ============================================================

WITH permission_codes AS (
    SELECT permission_code
    FROM (
        VALUES
            ('DASHBOARD_VIEW'),
            ('DASHBOARD_VIEW_STATISTICS'),

            ('HONEYTOKEN_VIEW'),
            ('HONEYTOKEN_VIEW_ACCESS_LOG'),

            ('CANARY_FILE_VIEW'),
            ('CANARY_FILE_VIEW_EVENTS'),

            ('ALERT_VIEW'),
            ('ALERT_VIEW_DETAILS'),
            ('ALERT_ACKNOWLEDGE'),
            ('ALERT_ESCALATE'),

            ('INCIDENT_VIEW'),
            ('INCIDENT_CREATE'),
            ('INCIDENT_ADD_NOTE'),
            ('INCIDENT_ADD_TIMELINE'),

            ('AI_MODEL_VIEW'),

            ('AI_ANALYSIS_VIEW'),
            ('AI_ANALYSIS_CREATE'),
            ('AI_ANALYSIS_EXECUTE'),
            ('AI_ANALYSIS_REVIEW'),
            ('AI_ANALYSIS_EXPORT'),

            ('REPORT_VIEW'),
            ('REPORT_CREATE'),
            ('REPORT_GENERATE'),
            ('REPORT_EXPORT')
    ) AS values_list(permission_code)
)

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permission_codes pc
JOIN permissions p
    ON p.permission_code = pc.permission_code
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'THREAT_ANALYST'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

-- ============================================================
-- 7. AI FORENSIC ANALYST
-- ============================================================

WITH permission_codes AS (
    SELECT permission_code
    FROM (
        VALUES
            ('DASHBOARD_VIEW'),
            ('DASHBOARD_VIEW_STATISTICS'),

            ('EVIDENCE_VIEW'),
            ('EVIDENCE_VIEW_SENSITIVE'),
            ('EVIDENCE_DOWNLOAD'),
            ('EVIDENCE_VERIFY_HASH'),
            ('EVIDENCE_VIEW_CUSTODY'),

            ('AI_MODEL_VIEW'),
            ('AI_MODEL_CREATE'),
            ('AI_MODEL_UPDATE'),
            ('AI_MODEL_ACTIVATE'),
            ('AI_MODEL_DEACTIVATE'),
            ('AI_MODEL_TEST'),
            ('AI_MODEL_CONFIGURE'),

            ('AI_ANALYSIS_VIEW'),
            ('AI_ANALYSIS_CREATE'),
            ('AI_ANALYSIS_EXECUTE'),
            ('AI_ANALYSIS_CANCEL'),
            ('AI_ANALYSIS_RETRY'),
            ('AI_ANALYSIS_REVIEW'),
            ('AI_ANALYSIS_APPROVE'),
            ('AI_ANALYSIS_EXPORT'),

            ('REPORT_VIEW'),
            ('REPORT_CREATE'),
            ('REPORT_GENERATE'),
            ('REPORT_EXPORT'),

            ('AUDIT_LOG_VIEW')
    ) AS values_list(permission_code)
)

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permission_codes pc
JOIN permissions p
    ON p.permission_code = pc.permission_code
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'AI_ANALYST'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

-- ============================================================
-- 8. INVESTIGATOR
-- ============================================================

WITH permission_codes AS (
    SELECT permission_code
    FROM (
        VALUES
            ('DASHBOARD_VIEW'),

            ('ALERT_VIEW'),
            ('ALERT_VIEW_DETAILS'),

            ('INCIDENT_VIEW'),
            ('INCIDENT_CREATE'),
            ('INCIDENT_UPDATE'),
            ('INCIDENT_ADD_TIMELINE'),
            ('INCIDENT_ADD_NOTE'),
            ('INCIDENT_EXPORT'),

            ('EVIDENCE_VIEW'),
            ('EVIDENCE_VIEW_SENSITIVE'),
            ('EVIDENCE_UPLOAD'),
            ('EVIDENCE_UPDATE_METADATA'),
            ('EVIDENCE_VERIFY_HASH'),
            ('EVIDENCE_DOWNLOAD'),
            ('EVIDENCE_ADD_CUSTODY_RECORD'),
            ('EVIDENCE_VIEW_CUSTODY'),

            ('AI_ANALYSIS_VIEW'),
            ('AI_ANALYSIS_CREATE'),
            ('AI_ANALYSIS_EXECUTE'),
            ('AI_ANALYSIS_REVIEW'),

            ('REPORT_VIEW'),
            ('REPORT_CREATE'),
            ('REPORT_GENERATE'),
            ('REPORT_EXPORT'),
            ('REPORT_PRINT')
    ) AS values_list(permission_code)
)

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permission_codes pc
JOIN permissions p
    ON p.permission_code = pc.permission_code
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'INVESTIGATOR'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

-- ============================================================
-- 9. SECURITY AUDITOR
-- ============================================================

WITH permission_codes AS (
    SELECT permission_code
    FROM (
        VALUES
            ('DASHBOARD_VIEW'),
            ('DASHBOARD_VIEW_STATISTICS'),
            ('DASHBOARD_VIEW_SENSITIVE_DATA'),

            ('ORGANIZATION_VIEW'),
            ('DEPARTMENT_VIEW'),
            ('USER_VIEW'),
            ('USER_VIEW_DETAILS'),
            ('ROLE_VIEW'),
            ('ROLE_VIEW_PERMISSIONS'),
            ('PERMISSION_VIEW'),

            ('AUTH_VIEW_SESSIONS'),
            ('AUTH_VIEW_LOGIN_HISTORY'),

            ('HONEYTOKEN_VIEW'),
            ('HONEYTOKEN_VIEW_ACCESS_LOG'),

            ('CANARY_FILE_VIEW'),
            ('CANARY_FILE_VIEW_EVENTS'),

            ('ALERT_VIEW'),
            ('ALERT_VIEW_DETAILS'),
            ('ALERT_EXPORT'),

            ('INCIDENT_VIEW'),
            ('INCIDENT_EXPORT'),

            ('EVIDENCE_VIEW'),
            ('EVIDENCE_VIEW_SENSITIVE'),
            ('EVIDENCE_VERIFY_HASH'),
            ('EVIDENCE_VIEW_CUSTODY'),

            ('AI_MODEL_VIEW'),
            ('AI_ANALYSIS_VIEW'),

            ('REPORT_VIEW'),
            ('REPORT_EXPORT'),

            ('SYSTEM_SETTING_VIEW'),

            ('FEATURE_FLAG_VIEW'),

            ('AUDIT_LOG_VIEW'),
            ('AUDIT_LOG_VIEW_SENSITIVE'),
            ('AUDIT_LOG_EXPORT'),
            ('AUDIT_LOG_VERIFY'),

            ('BACKUP_VIEW'),

            ('SYNC_VIEW')
    ) AS values_list(permission_code)
)

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permission_codes pc
JOIN permissions p
    ON p.permission_code = pc.permission_code
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'AUDITOR'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

-- ============================================================
-- 10. READ-ONLY VIEWER
-- ============================================================

WITH permission_codes AS (
    SELECT permission_code
    FROM (
        VALUES
            ('DASHBOARD_VIEW'),

            ('ORGANIZATION_VIEW'),
            ('DEPARTMENT_VIEW'),

            ('ALERT_VIEW'),

            ('INCIDENT_VIEW'),

            ('REPORT_VIEW')
    ) AS values_list(permission_code)
)

INSERT INTO role_permissions (
    role_id,
    permission_id,
    granted_by,
    granted_at,
    expires_at,
    is_active
)
SELECT
    r.id,
    p.id,
    NULL,
    CURRENT_TIMESTAMP,
    NULL,
    TRUE
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
CROSS JOIN permission_codes pc
JOIN permissions p
    ON p.permission_code = pc.permission_code
WHERE o.organization_code = 'CSL001'
  AND r.role_code = 'VIEWER'
  AND r.deleted_at IS NULL
  AND p.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM role_permissions rp
      WHERE rp.role_id = r.id
        AND rp.permission_id = p.id
  );

COMMIT;

-- ============================================================
-- VERIFICATION 1: Permission count for each role
-- ============================================================

SELECT
    r.role_code,
    r.role_name,
    COUNT(rp.permission_id) AS permission_count
FROM roles r
JOIN organizations o
    ON o.id = r.organization_id
LEFT JOIN role_permissions rp
    ON rp.role_id = r.id
   AND rp.is_active = TRUE
WHERE o.organization_code = 'CSL001'
  AND r.deleted_at IS NULL
GROUP BY
    r.role_code,
    r.role_name,
    r.priority_level
ORDER BY r.priority_level;

-- ============================================================
-- VERIFICATION 2: Display permissions assigned to each role
-- ============================================================

SELECT
    r.role_code,
    p.module_name,
    p.permission_code,
    p.permission_name,
    p.risk_level,
    p.requires_approval,
    rp.is_active
FROM role_permissions rp
JOIN roles r
    ON r.id = rp.role_id
JOIN organizations o
    ON o.id = r.organization_id
JOIN permissions p
    ON p.id = rp.permission_id
WHERE o.organization_code = 'CSL001'
ORDER BY
    r.priority_level,
    p.module_name,
    p.permission_code;