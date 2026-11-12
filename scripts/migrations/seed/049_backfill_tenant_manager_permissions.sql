-- Existing tenant MANAGER roles predate the Honeytoken, complete role
-- management and audit-log navigation. Grant those tenant-scoped capabilities
-- without granting platform-wide SUPER_ADMIN access.
BEGIN;

WITH manager_permissions(permission_code) AS (
    VALUES
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
        ('HONEYTOKEN_DELETE'),
        ('HONEYTOKEN_DEPLOY'),
        ('HONEYTOKEN_DEACTIVATE'),
        ('HONEYTOKEN_VIEW_ACCESS_LOG'),
        ('HONEYTOKEN_VERIFY'),
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
CROSS JOIN manager_permissions AS mp
JOIN permissions AS p
    ON UPPER(p.permission_code) = mp.permission_code
    AND UPPER(p.status) = 'ACTIVE'
WHERE UPPER(r.role_code) = 'MANAGER'
  AND r.deleted_at IS NULL
ON CONFLICT (role_id, permission_id) DO UPDATE
SET is_active = TRUE,
    expires_at = NULL;

COMMIT;
