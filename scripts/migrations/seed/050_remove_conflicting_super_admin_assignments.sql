-- A user with an operational tenant role must not simultaneously inherit the
-- platform-wide SUPER_ADMIN role. Keep dedicated super-admin accounts intact
-- and remove only conflicting mixed assignments.
BEGIN;

UPDATE user_roles AS super_assignment
SET is_active = FALSE,
    status = 'REVOKED',
    updated_at = CURRENT_TIMESTAMP
FROM roles AS super_role
WHERE super_role.id = super_assignment.role_id
  AND UPPER(super_role.role_code) = 'SUPER_ADMIN'
  AND super_assignment.is_active = TRUE
  AND EXISTS (
      SELECT 1
      FROM user_roles AS tenant_assignment
      JOIN roles AS tenant_role
        ON tenant_role.id = tenant_assignment.role_id
      WHERE tenant_assignment.user_id = super_assignment.user_id
        AND tenant_assignment.id <> super_assignment.id
        AND tenant_assignment.is_active = TRUE
        AND UPPER(tenant_assignment.status) = 'ACTIVE'
        AND UPPER(tenant_role.role_code) <> 'SUPER_ADMIN'
        AND tenant_role.deleted_at IS NULL
  );

COMMIT;
