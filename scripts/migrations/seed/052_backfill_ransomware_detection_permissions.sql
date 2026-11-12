-- Tenant administrators and managers operate their organization's ransomware
-- early-detection queue. Repository queries continue to enforce tenant scope.
BEGIN;

WITH ransomware_permissions(permission_code) AS (
    VALUES
        ('THREAT_VIEW'),
        ('PRE_ENCRYPTION_VIEW'),
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
CROSS JOIN ransomware_permissions AS rp
JOIN permissions AS p
    ON UPPER(p.permission_code) = rp.permission_code
    AND UPPER(p.status) = 'ACTIVE'
WHERE (
        UPPER(r.role_code) IN ('MANAGER', 'ORG_ADMIN', 'ORGANIZATION_ADMIN')
        OR (
            UPPER(r.role_code) LIKE '%ADMIN%'
            AND UPPER(r.role_code) <> 'SUPER_ADMIN'
        )
    )
  AND r.deleted_at IS NULL
ON CONFLICT (role_id, permission_id) DO UPDATE
SET is_active = TRUE,
    expires_at = NULL;

COMMIT;
