-- Backfill primary IAM, deception and audit permissions in existing databases.
BEGIN;
INSERT INTO permissions (permission_code, permission_name, module_name, action_name, description, risk_level, requires_approval, status)
VALUES
('ORGANIZATION_VIEW','View Organizations','ORGANIZATION','VIEW','View organization records.','LOW',FALSE,'ACTIVE'),
('USER_VIEW','View Users','USER','VIEW','View users in the permitted organization.','LOW',FALSE,'ACTIVE'),
('USER_VIEW_DETAILS','View User Details','USER','VIEW_DETAILS','View user profile and access details.','MEDIUM',FALSE,'ACTIVE'),
('USER_CREATE','Create User','USER','CREATE','Create users in the permitted organization.','HIGH',FALSE,'ACTIVE'),
('USER_UPDATE','Update User','USER','UPDATE','Update user profile and account state.','HIGH',FALSE,'ACTIVE'),
('USER_ASSIGN_ROLE','Assign User Role','USER','ASSIGN_ROLE','Assign an approved role to a user.','HIGH',TRUE,'ACTIVE'),
('USER_DISABLE','Disable User','USER','DISABLE','Disable a user account.','HIGH',TRUE,'ACTIVE'),
('ROLE_VIEW','View Roles','ROLE','VIEW','View organization roles.','LOW',FALSE,'ACTIVE'),
('ROLE_CREATE','Create Role','ROLE','CREATE','Create an organization role.','HIGH',FALSE,'ACTIVE'),
('ROLE_UPDATE','Update Role','ROLE','UPDATE','Update an organization role.','HIGH',FALSE,'ACTIVE'),
('ROLE_DELETE','Delete Role','ROLE','DELETE','Deactivate an organization role.','HIGH',TRUE,'ACTIVE'),
('ROLE_VIEW_PERMISSIONS','View Role Permissions','ROLE','VIEW_PERMISSIONS','View permissions assigned to a role.','MEDIUM',FALSE,'ACTIVE'),
('ROLE_MANAGE_PERMISSIONS','Manage Role Permissions','ROLE','MANAGE_PERMISSIONS','Grant and revoke role permissions.','CRITICAL',TRUE,'ACTIVE'),
('PERMISSION_VIEW','View Permission Catalogue','PERMISSION','VIEW','View the platform permission catalogue.','MEDIUM',FALSE,'ACTIVE'),
('HONEYTOKEN_VIEW','View Honeytokens','HONEYTOKEN','VIEW','View honeytoken records.','MEDIUM',FALSE,'ACTIVE'),
('HONEYTOKEN_CREATE','Create Honeytoken','HONEYTOKEN','CREATE','Generate a new honeytoken.','HIGH',FALSE,'ACTIVE'),
('HONEYTOKEN_UPDATE','Update Honeytoken','HONEYTOKEN','UPDATE','Update honeytoken configuration.','HIGH',FALSE,'ACTIVE'),
('HONEYTOKEN_DELETE','Delete Honeytoken','HONEYTOKEN','DELETE','Delete or deactivate a honeytoken.','HIGH',TRUE,'ACTIVE'),
('HONEYTOKEN_DEPLOY','Deploy Honeytoken','HONEYTOKEN','DEPLOY','Record and arm an approved honeytoken placement.','HIGH',FALSE,'ACTIVE'),
('HONEYTOKEN_DEACTIVATE','Deactivate Honeytoken','HONEYTOKEN','DEACTIVATE','Stop monitoring an active honeytoken.','HIGH',TRUE,'ACTIVE'),
('HONEYTOKEN_VIEW_ACCESS_LOG','View Honeytoken Access Log','HONEYTOKEN','VIEW_ACCESS_LOG','View honeytoken access and trigger history.','HIGH',FALSE,'ACTIVE'),
('HONEYTOKEN_VERIFY','Verify Honeytoken','HONEYTOKEN','VERIFY','Validate an observed honeytoken value.','MEDIUM',FALSE,'ACTIVE'),
('AUDIT_LOG_VIEW','View Audit Activity','AUDIT_LOG','VIEW','View organization-scoped audit activity.','HIGH',FALSE,'ACTIVE'),
('AUDIT_LOG_EXPORT','Export Audit Activity','AUDIT_LOG','EXPORT','Export organization-scoped audit activity.','HIGH',TRUE,'ACTIVE')
ON CONFLICT (permission_code) DO UPDATE SET permission_name=EXCLUDED.permission_name,module_name=EXCLUDED.module_name,action_name=EXCLUDED.action_name,description=EXCLUDED.description,risk_level=EXCLUDED.risk_level,requires_approval=EXCLUDED.requires_approval,status='ACTIVE';
COMMIT;
