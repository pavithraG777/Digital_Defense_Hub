-- Give every tenant administrator the core tenant-scoped screens introduced
-- after the organization was provisioned.  Data access remains constrained by
-- the organization_id carried in the authenticated JWT and repository queries.
BEGIN;

WITH tenant_admin_permissions(permission_code) AS (
    VALUES
        ('ORGANIZATION_VIEW'),
        ('USER_VIEW'),
        ('USER_VIEW_DETAILS'),
        ('USER_CREATE'),
        ('USER_UPDATE'),
        ('USER_ASSIGN_ROLE'),
        ('USER_DISABLE'),
        ('ROLE_VIEW'),
        ('ROLE_CREATE'),
        ('ROLE_UPDATE'),
        ('ROLE_DELETE'),
        ('ROLE_VIEW_PERMISSIONS'),
        ('ROLE_MANAGE_PERMISSIONS'),
        ('PERMISSION_VIEW'),
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
        ('AUDIT_LOG_VIEW'),
        ('AUDIT_LOG_EXPORT'),
        ('ORGANIZATION_MANAGE_SECURITY')
)
INSERT INTO role_permissions (
    role_id, permission_id, granted_by, granted_at, expires_at, is_active
)
SELECT
    r.id, p.id, NULL, CURRENT_TIMESTAMP, NULL, TRUE
FROM roles AS r
JOIN organizations AS o
    ON o.id = r.organization_id
    AND o.deleted_at IS NULL
CROSS JOIN tenant_admin_permissions AS tap
JOIN permissions AS p
    ON UPPER(p.permission_code) = tap.permission_code
    AND UPPER(p.status) = 'ACTIVE'
WHERE UPPER(r.role_code) IN ('ORG_ADMIN', 'ORGANIZATION_ADMIN')
  AND r.deleted_at IS NULL
ON CONFLICT (role_id, permission_id) DO UPDATE
SET is_active = TRUE,
    expires_at = NULL;

COMMIT;
