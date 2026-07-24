-- ============================================================
-- FILE NAME : 04_seed_permissions.sql
-- PURPOSE   : Insert platform permissions
-- PROJECT   : Offline-First Cyber Security and
--             Digital Forensics Platform
-- ============================================================

BEGIN;

WITH permission_seed AS (
    SELECT *
    FROM (
        VALUES

        -- =====================================================
        -- DASHBOARD
        -- =====================================================

        (
            'DASHBOARD_VIEW',
            'View Dashboard',
            'DASHBOARD',
            'VIEW',
            'View the main security dashboard.',
            'LOW',
            FALSE
        ),
        (
            'DASHBOARD_VIEW_STATISTICS',
            'View Dashboard Statistics',
            'DASHBOARD',
            'VIEW_STATISTICS',
            'View security statistics and summary counts.',
            'LOW',
            FALSE
        ),
        (
            'DASHBOARD_VIEW_SENSITIVE_DATA',
            'View Sensitive Dashboard Data',
            'DASHBOARD',
            'VIEW_SENSITIVE_DATA',
            'View confidential dashboard information.',
            'HIGH',
            FALSE
        ),
        (
            'DASHBOARD_EXPORT',
            'Export Dashboard',
            'DASHBOARD',
            'EXPORT',
            'Export dashboard information.',
            'MEDIUM',
            FALSE
        ),
        (
            'DASHBOARD_CUSTOMIZE',
            'Customize Dashboard',
            'DASHBOARD',
            'CUSTOMIZE',
            'Customize dashboard widgets and layout.',
            'LOW',
            FALSE
        ),

        -- =====================================================
        -- ORGANIZATION MANAGEMENT
        -- =====================================================

        (
            'ORGANIZATION_VIEW',
            'View Organization',
            'ORGANIZATION',
            'VIEW',
            'View organization information.',
            'LOW',
            FALSE
        ),
        (
            'ORGANIZATION_CREATE',
            'Create Organization',
            'ORGANIZATION',
            'CREATE',
            'Create a new organization.',
            'CRITICAL',
            TRUE
        ),
        (
            'ORGANIZATION_UPDATE',
            'Update Organization',
            'ORGANIZATION',
            'UPDATE',
            'Update organization information.',
            'HIGH',
            TRUE
        ),
        (
            'ORGANIZATION_DELETE',
            'Delete Organization',
            'ORGANIZATION',
            'DELETE',
            'Soft delete an organization.',
            'CRITICAL',
            TRUE
        ),
        (
            'ORGANIZATION_APPROVE',
            'Approve Organization',
            'ORGANIZATION',
            'APPROVE',
            'Approve a registered organization.',
            'CRITICAL',
            TRUE
        ),
        (
            'ORGANIZATION_SUSPEND',
            'Suspend Organization',
            'ORGANIZATION',
            'SUSPEND',
            'Suspend an organization account.',
            'CRITICAL',
            TRUE
        ),
        (
            'ORGANIZATION_RESTORE',
            'Restore Organization',
            'ORGANIZATION',
            'RESTORE',
            'Restore a suspended or deleted organization.',
            'CRITICAL',
            TRUE
        ),
        (
            'ORGANIZATION_MANAGE_SECURITY',
            'Manage Organization Security',
            'ORGANIZATION',
            'MANAGE_SECURITY',
            'Manage organization security configurations.',
            'CRITICAL',
            TRUE
        ),

        -- =====================================================
        -- DEPARTMENT MANAGEMENT
        -- =====================================================

        (
            'DEPARTMENT_VIEW',
            'View Departments',
            'DEPARTMENT',
            'VIEW',
            'View department information.',
            'LOW',
            FALSE
        ),
        (
            'DEPARTMENT_CREATE',
            'Create Department',
            'DEPARTMENT',
            'CREATE',
            'Create a new department.',
            'MEDIUM',
            FALSE
        ),
        (
            'DEPARTMENT_UPDATE',
            'Update Department',
            'DEPARTMENT',
            'UPDATE',
            'Update department information.',
            'MEDIUM',
            FALSE
        ),
        (
            'DEPARTMENT_DELETE',
            'Delete Department',
            'DEPARTMENT',
            'DELETE',
            'Soft delete a department.',
            'HIGH',
            TRUE
        ),
        (
            'DEPARTMENT_ASSIGN_PARENT',
            'Assign Parent Department',
            'DEPARTMENT',
            'ASSIGN_PARENT',
            'Assign a parent department.',
            'MEDIUM',
            FALSE
        ),
        (
            'DEPARTMENT_MANAGE_SECURITY',
            'Manage Department Security',
            'DEPARTMENT',
            'MANAGE_SECURITY',
            'Manage department security level and module access.',
            'HIGH',
            TRUE
        ),

        -- =====================================================
        -- USER MANAGEMENT
        -- =====================================================

        (
            'USER_VIEW',
            'View Users',
            'USER',
            'VIEW',
            'View platform users.',
            'LOW',
            FALSE
        ),
        (
            'USER_VIEW_DETAILS',
            'View User Details',
            'USER',
            'VIEW_DETAILS',
            'View detailed user information.',
            'MEDIUM',
            FALSE
        ),
        (
            'USER_CREATE',
            'Create User',
            'USER',
            'CREATE',
            'Create a new user account.',
            'HIGH',
            FALSE
        ),
        (
            'USER_UPDATE',
            'Update User',
            'USER',
            'UPDATE',
            'Update user account information.',
            'HIGH',
            FALSE
        ),
        (
            'USER_DELETE',
            'Delete User',
            'USER',
            'DELETE',
            'Soft delete a user account.',
            'CRITICAL',
            TRUE
        ),
        (
            'USER_ACTIVATE',
            'Activate User',
            'USER',
            'ACTIVATE',
            'Activate a user account.',
            'HIGH',
            FALSE
        ),
        (
            'USER_DEACTIVATE',
            'Deactivate User',
            'USER',
            'DEACTIVATE',
            'Deactivate a user account.',
            'HIGH',
            TRUE
        ),
        (
            'USER_LOCK',
            'Lock User Account',
            'USER',
            'LOCK',
            'Lock a user account.',
            'HIGH',
            TRUE
        ),
        (
            'USER_UNLOCK',
            'Unlock User Account',
            'USER',
            'UNLOCK',
            'Unlock a locked user account.',
            'HIGH',
            FALSE
        ),
        (
            'USER_RESET_PASSWORD',
            'Reset User Password',
            'USER',
            'RESET_PASSWORD',
            'Reset another user password.',
            'CRITICAL',
            TRUE
        ),
        (
            'USER_MANAGE_MFA',
            'Manage User MFA',
            'USER',
            'MANAGE_MFA',
            'Enable or disable multi-factor authentication.',
            'CRITICAL',
            TRUE
        ),
        (
            'USER_EXPORT',
            'Export Users',
            'USER',
            'EXPORT',
            'Export user information.',
            'HIGH',
            TRUE
        ),

        -- =====================================================
        -- ROLE MANAGEMENT
        -- =====================================================

        (
            'ROLE_VIEW',
            'View Roles',
            'ROLE',
            'VIEW',
            'View platform roles.',
            'LOW',
            FALSE
        ),
        (
            'ROLE_CREATE',
            'Create Role',
            'ROLE',
            'CREATE',
            'Create a new role.',
            'HIGH',
            FALSE
        ),
        (
            'ROLE_UPDATE',
            'Update Role',
            'ROLE',
            'UPDATE',
            'Update role information.',
            'HIGH',
            FALSE
        ),
        (
            'ROLE_DELETE',
            'Delete Role',
            'ROLE',
            'DELETE',
            'Delete a role.',
            'CRITICAL',
            TRUE
        ),
        (
            'ROLE_ASSIGN',
            'Assign Role',
            'ROLE',
            'ASSIGN',
            'Assign a role to a user.',
            'HIGH',
            FALSE
        ),
        (
            'ROLE_REVOKE',
            'Revoke Role',
            'ROLE',
            'REVOKE',
            'Revoke a role from a user.',
            'HIGH',
            TRUE
        ),
        (
            'ROLE_VIEW_PERMISSIONS',
            'View Role Permissions',
            'ROLE',
            'VIEW_PERMISSIONS',
            'View permissions assigned to roles.',
            'LOW',
            FALSE
        ),
        (
            'ROLE_MANAGE_PERMISSIONS',
            'Manage Role Permissions',
            'ROLE',
            'MANAGE_PERMISSIONS',
            'Grant or revoke permissions for roles.',
            'CRITICAL',
            TRUE
        ),

        -- =====================================================
        -- PERMISSION MANAGEMENT
        -- =====================================================

        (
            'PERMISSION_VIEW',
            'View Permissions',
            'PERMISSION',
            'VIEW',
            'View platform permissions.',
            'LOW',
            FALSE
        ),
        (
            'PERMISSION_CREATE',
            'Create Permission',
            'PERMISSION',
            'CREATE',
            'Create a new permission.',
            'CRITICAL',
            TRUE
        ),
        (
            'PERMISSION_UPDATE',
            'Update Permission',
            'PERMISSION',
            'UPDATE',
            'Update permission information.',
            'CRITICAL',
            TRUE
        ),
        (
            'PERMISSION_DISABLE',
            'Disable Permission',
            'PERMISSION',
            'DISABLE',
            'Disable an existing permission.',
            'CRITICAL',
            TRUE
        ),

        -- =====================================================
        -- AUTHENTICATION
        -- =====================================================

        (
            'AUTH_VIEW_SESSIONS',
            'View User Sessions',
            'AUTHENTICATION',
            'VIEW_SESSIONS',
            'View active authentication sessions.',
            'MEDIUM',
            FALSE
        ),
        (
            'AUTH_REVOKE_SESSION',
            'Revoke User Session',
            'AUTHENTICATION',
            'REVOKE_SESSION',
            'Terminate an active user session.',
            'HIGH',
            TRUE
        ),
        (
            'AUTH_VIEW_LOGIN_HISTORY',
            'View Login History',
            'AUTHENTICATION',
            'VIEW_LOGIN_HISTORY',
            'View user login history.',
            'MEDIUM',
            FALSE
        ),
        (
            'AUTH_MANAGE_PASSWORD_POLICY',
            'Manage Password Policy',
            'AUTHENTICATION',
            'MANAGE_PASSWORD_POLICY',
            'Manage password security requirements.',
            'CRITICAL',
            TRUE
        ),
        (
            'AUTH_MANAGE_MFA_POLICY',
            'Manage MFA Policy',
            'AUTHENTICATION',
            'MANAGE_MFA_POLICY',
            'Manage platform MFA requirements.',
            'CRITICAL',
            TRUE
        ),

        -- =====================================================
        -- HONEYTOKEN MANAGEMENT
        -- =====================================================

        (
            'HONEYTOKEN_VIEW',
            'View Honeytokens',
            'HONEYTOKEN',
            'VIEW',
            'View honeytoken records.',
            'MEDIUM',
            FALSE
        ),
        (
            'HONEYTOKEN_CREATE',
            'Create Honeytoken',
            'HONEYTOKEN',
            'CREATE',
            'Create and deploy a honeytoken.',
            'HIGH',
            FALSE
        ),
        (
            'HONEYTOKEN_UPDATE',
            'Update Honeytoken',
            'HONEYTOKEN',
            'UPDATE',
            'Update honeytoken configuration.',
            'HIGH',
            FALSE
        ),
        (
            'HONEYTOKEN_DELETE',
            'Delete Honeytoken',
            'HONEYTOKEN',
            'DELETE',
            'Delete or deactivate a honeytoken.',
            'HIGH',
            TRUE
        ),
        (
            'HONEYTOKEN_DEPLOY',
            'Deploy Honeytoken',
            'HONEYTOKEN',
            'DEPLOY',
            'Deploy a honeytoken to a protected location.',
            'HIGH',
            FALSE
        ),
        (
            'HONEYTOKEN_DEACTIVATE',
            'Deactivate Honeytoken',
            'HONEYTOKEN',
            'DEACTIVATE',
            'Deactivate an active honeytoken.',
            'HIGH',
            TRUE
        ),
        (
            'HONEYTOKEN_VIEW_ACCESS_LOG',
            'View Honeytoken Access Log',
            'HONEYTOKEN',
            'VIEW_ACCESS_LOG',
            'View honeytoken access and trigger history.',
            'HIGH',
            FALSE
        ),
        (
            'HONEYTOKEN_VERIFY',
            'Verify Honeytoken',
            'HONEYTOKEN',
            'VERIFY',
            'Verify honeytoken integrity and deployment.',
            'MEDIUM',
            FALSE
        ),

        -- =====================================================
        -- CANARY FILE MANAGEMENT
        -- =====================================================

        (
            'CANARY_FILE_VIEW',
            'View Canary Files',
            'CANARY_FILE',
            'VIEW',
            'View canary file records.',
            'MEDIUM',
            FALSE
        ),
        (
            'CANARY_FILE_CREATE',
            'Create Canary File',
            'CANARY_FILE',
            'CREATE',
            'Create a new canary file.',
            'HIGH',
            FALSE
        ),
        (
            'CANARY_FILE_UPDATE',
            'Update Canary File',
            'CANARY_FILE',
            'UPDATE',
            'Update canary file configuration.',
            'HIGH',
            FALSE
        ),
        (
            'CANARY_FILE_DELETE',
            'Delete Canary File',
            'CANARY_FILE',
            'DELETE',
            'Delete a canary file.',
            'HIGH',
            TRUE
        ),
        (
            'CANARY_FILE_DEPLOY',
            'Deploy Canary File',
            'CANARY_FILE',
            'DEPLOY',
            'Deploy a canary file to a monitored system.',
            'HIGH',
            FALSE
        ),
        (
            'CANARY_FILE_VERIFY',
            'Verify Canary File',
            'CANARY_FILE',
            'VERIFY',
            'Verify canary file integrity.',
            'MEDIUM',
            FALSE
        ),
        (
            'CANARY_FILE_VIEW_EVENTS',
            'View Canary File Events',
            'CANARY_FILE',
            'VIEW_EVENTS',
            'View access, modification and deletion events.',
            'HIGH',
            FALSE
        ),
        (
            'CANARY_FILE_REGENERATE',
            'Regenerate Canary File',
            'CANARY_FILE',
            'REGENERATE',
            'Generate a replacement canary file.',
            'HIGH',
            TRUE
        ),

        -- =====================================================
        -- ALERT MANAGEMENT
        -- =====================================================

        (
            'ALERT_VIEW',
            'View Alerts',
            'ALERT',
            'VIEW',
            'View security alerts.',
            'LOW',
            FALSE
        ),
        (
            'ALERT_VIEW_DETAILS',
            'View Alert Details',
            'ALERT',
            'VIEW_DETAILS',
            'View complete alert information.',
            'MEDIUM',
            FALSE
        ),
        (
            'ALERT_ACKNOWLEDGE',
            'Acknowledge Alert',
            'ALERT',
            'ACKNOWLEDGE',
            'Acknowledge a security alert.',
            'MEDIUM',
            FALSE
        ),
        (
            'ALERT_ASSIGN',
            'Assign Alert',
            'ALERT',
            'ASSIGN',
            'Assign an alert to an analyst.',
            'MEDIUM',
            FALSE
        ),
        (
            'ALERT_UPDATE_STATUS',
            'Update Alert Status',
            'ALERT',
            'UPDATE_STATUS',
            'Update alert investigation status.',
            'MEDIUM',
            FALSE
        ),
        (
            'ALERT_ESCALATE',
            'Escalate Alert',
            'ALERT',
            'ESCALATE',
            'Escalate a high-risk alert.',
            'HIGH',
            FALSE
        ),
        (
            'ALERT_CLOSE',
            'Close Alert',
            'ALERT',
            'CLOSE',
            'Close a resolved or false-positive alert.',
            'HIGH',
            FALSE
        ),
        (
            'ALERT_DELETE',
            'Delete Alert',
            'ALERT',
            'DELETE',
            'Delete an alert record.',
            'CRITICAL',
            TRUE
        ),
        (
            'ALERT_EXPORT',
            'Export Alerts',
            'ALERT',
            'EXPORT',
            'Export security alert information.',
            'HIGH',
            TRUE
        ),

        -- =====================================================
        -- INCIDENT MANAGEMENT
        -- =====================================================

        (
            'INCIDENT_VIEW',
            'View Incidents',
            'INCIDENT',
            'VIEW',
            'View cyber security incidents.',
            'LOW',
            FALSE
        ),
        (
            'INCIDENT_CREATE',
            'Create Incident',
            'INCIDENT',
            'CREATE',
            'Create a cyber security incident.',
            'MEDIUM',
            FALSE
        ),
        (
            'INCIDENT_UPDATE',
            'Update Incident',
            'INCIDENT',
            'UPDATE',
            'Update incident information.',
            'HIGH',
            FALSE
        ),
        (
            'INCIDENT_ASSIGN',
            'Assign Incident',
            'INCIDENT',
            'ASSIGN',
            'Assign an incident to an investigator.',
            'MEDIUM',
            FALSE
        ),
        (
            'INCIDENT_CHANGE_PRIORITY',
            'Change Incident Priority',
            'INCIDENT',
            'CHANGE_PRIORITY',
            'Change incident priority level.',
            'HIGH',
            FALSE
        ),
        (
            'INCIDENT_ESCALATE',
            'Escalate Incident',
            'INCIDENT',
            'ESCALATE',
            'Escalate an incident for immediate response.',
            'HIGH',
            FALSE
        ),
        (
            'INCIDENT_ADD_TIMELINE',
            'Add Incident Timeline',
            'INCIDENT',
            'ADD_TIMELINE',
            'Add an event to the incident timeline.',
            'MEDIUM',
            FALSE
        ),
        (
            'INCIDENT_ADD_NOTE',
            'Add Incident Note',
            'INCIDENT',
            'ADD_NOTE',
            'Add investigation notes to an incident.',
            'MEDIUM',
            FALSE
        ),
        (
            'INCIDENT_CONTAIN',
            'Contain Incident',
            'INCIDENT',
            'CONTAIN',
            'Mark an incident as contained.',
            'HIGH',
            FALSE
        ),
        (
            'INCIDENT_RESOLVE',
            'Resolve Incident',
            'INCIDENT',
            'RESOLVE',
            'Mark an incident as resolved.',
            'HIGH',
            FALSE
        ),
        (
            'INCIDENT_CLOSE',
            'Close Incident',
            'INCIDENT',
            'CLOSE',
            'Close an incident investigation.',
            'HIGH',
            TRUE
        ),
        (
            'INCIDENT_REOPEN',
            'Reopen Incident',
            'INCIDENT',
            'REOPEN',
            'Reopen a closed incident.',
            'HIGH',
            TRUE
        ),
        (
            'INCIDENT_DELETE',
            'Delete Incident',
            'INCIDENT',
            'DELETE',
            'Delete an incident record.',
            'CRITICAL',
            TRUE
        ),
        (
            'INCIDENT_EXPORT',
            'Export Incidents',
            'INCIDENT',
            'EXPORT',
            'Export incident information.',
            'HIGH',
            TRUE
        ),

        -- =====================================================
        -- DIGITAL EVIDENCE MANAGEMENT
        -- =====================================================

        (
            'EVIDENCE_VIEW',
            'View Evidence',
            'EVIDENCE',
            'VIEW',
            'View digital evidence records.',
            'HIGH',
            FALSE
        ),
        (
            'EVIDENCE_VIEW_SENSITIVE',
            'View Sensitive Evidence',
            'EVIDENCE',
            'VIEW_SENSITIVE',
            'View restricted digital evidence.',
            'CRITICAL',
            TRUE
        ),
        (
            'EVIDENCE_UPLOAD',
            'Upload Evidence',
            'EVIDENCE',
            'UPLOAD',
            'Upload a digital evidence file.',
            'HIGH',
            FALSE
        ),
        (
            'EVIDENCE_UPDATE_METADATA',
            'Update Evidence Metadata',
            'EVIDENCE',
            'UPDATE_METADATA',
            'Update evidence metadata.',
            'HIGH',
            FALSE
        ),
        (
            'EVIDENCE_VERIFY_HASH',
            'Verify Evidence Hash',
            'EVIDENCE',
            'VERIFY_HASH',
            'Verify evidence integrity using file hashes.',
            'HIGH',
            FALSE
        ),
        (
            'EVIDENCE_DOWNLOAD',
            'Download Evidence',
            'EVIDENCE',
            'DOWNLOAD',
            'Download an evidence file.',
            'CRITICAL',
            TRUE
        ),
        (
            'EVIDENCE_EXPORT',
            'Export Evidence',
            'EVIDENCE',
            'EXPORT',
            'Export digital evidence.',
            'CRITICAL',
            TRUE
        ),
        (
            'EVIDENCE_DELETE',
            'Delete Evidence',
            'EVIDENCE',
            'DELETE',
            'Delete a digital evidence record.',
            'CRITICAL',
            TRUE
        ),
        (
            'EVIDENCE_ARCHIVE',
            'Archive Evidence',
            'EVIDENCE',
            'ARCHIVE',
            'Archive digital evidence.',
            'HIGH',
            TRUE
        ),
        (
            'EVIDENCE_RESTORE',
            'Restore Evidence',
            'EVIDENCE',
            'RESTORE',
            'Restore archived evidence.',
            'HIGH',
            TRUE
        ),
        (
            'EVIDENCE_ADD_CUSTODY_RECORD',
            'Add Chain of Custody Record',
            'EVIDENCE',
            'ADD_CUSTODY_RECORD',
            'Add an evidence chain of custody entry.',
            'HIGH',
            FALSE
        ),
        (
            'EVIDENCE_TRANSFER_CUSTODY',
            'Transfer Evidence Custody',
            'EVIDENCE',
            'TRANSFER_CUSTODY',
            'Transfer evidence custody to another authorized user.',
            'CRITICAL',
            TRUE
        ),
        (
            'EVIDENCE_VIEW_CUSTODY',
            'View Chain of Custody',
            'EVIDENCE',
            'VIEW_CUSTODY',
            'View the evidence chain of custody.',
            'HIGH',
            FALSE
        ),
        (
            'EVIDENCE_LOCK',
            'Lock Evidence',
            'EVIDENCE',
            'LOCK',
            'Prevent changes to an evidence record.',
            'CRITICAL',
            TRUE
        ),
        (
            'EVIDENCE_UNLOCK',
            'Unlock Evidence',
            'EVIDENCE',
            'UNLOCK',
            'Unlock an evidence record.',
            'CRITICAL',
            TRUE
        ),

        -- =====================================================
        -- AI MODEL MANAGEMENT
        -- =====================================================

        (
            'AI_MODEL_VIEW',
            'View AI Models',
            'AI_MODEL',
            'VIEW',
            'View registered AI models.',
            'LOW',
            FALSE
        ),
        (
            'AI_MODEL_CREATE',
            'Register AI Model',
            'AI_MODEL',
            'CREATE',
            'Register a new AI model.',
            'HIGH',
            FALSE
        ),
        (
            'AI_MODEL_UPDATE',
            'Update AI Model',
            'AI_MODEL',
            'UPDATE',
            'Update AI model information.',
            'HIGH',
            FALSE
        ),
        (
            'AI_MODEL_DELETE',
            'Delete AI Model',
            'AI_MODEL',
            'DELETE',
            'Delete an AI model.',
            'CRITICAL',
            TRUE
        ),
        (
            'AI_MODEL_ACTIVATE',
            'Activate AI Model',
            'AI_MODEL',
            'ACTIVATE',
            'Activate an AI model for analysis.',
            'HIGH',
            FALSE
        ),
        (
            'AI_MODEL_DEACTIVATE',
            'Deactivate AI Model',
            'AI_MODEL',
            'DEACTIVATE',
            'Deactivate an AI model.',
            'HIGH',
            TRUE
        ),
        (
            'AI_MODEL_TEST',
            'Test AI Model',
            'AI_MODEL',
            'TEST',
            'Run model validation and testing.',
            'MEDIUM',
            FALSE
        ),
        (
            'AI_MODEL_CONFIGURE',
            'Configure AI Model',
            'AI_MODEL',
            'CONFIGURE',
            'Configure model execution settings.',
            'HIGH',
            TRUE
        ),

        -- =====================================================
        -- AI ANALYSIS
        -- =====================================================

        (
            'AI_ANALYSIS_VIEW',
            'View AI Analysis',
            'AI_ANALYSIS',
            'VIEW',
            'View AI analysis records.',
            'MEDIUM',
            FALSE
        ),
        (
            'AI_ANALYSIS_CREATE',
            'Create AI Analysis',
            'AI_ANALYSIS',
            'CREATE',
            'Create a new AI analysis request.',
            'HIGH',
            FALSE
        ),
        (
            'AI_ANALYSIS_EXECUTE',
            'Execute AI Analysis',
            'AI_ANALYSIS',
            'EXECUTE',
            'Execute an offline AI model.',
            'HIGH',
            FALSE
        ),
        (
            'AI_ANALYSIS_CANCEL',
            'Cancel AI Analysis',
            'AI_ANALYSIS',
            'CANCEL',
            'Cancel an active AI analysis.',
            'MEDIUM',
            FALSE
        ),
        (
            'AI_ANALYSIS_RETRY',
            'Retry AI Analysis',
            'AI_ANALYSIS',
            'RETRY',
            'Retry a failed AI analysis.',
            'MEDIUM',
            FALSE
        ),
        (
            'AI_ANALYSIS_REVIEW',
            'Review AI Analysis',
            'AI_ANALYSIS',
            'REVIEW',
            'Review AI-generated analysis results.',
            'HIGH',
            FALSE
        ),
        (
            'AI_ANALYSIS_APPROVE',
            'Approve AI Analysis',
            'AI_ANALYSIS',
            'APPROVE',
            'Approve an AI analysis result.',
            'HIGH',
            TRUE
        ),
        (
            'AI_ANALYSIS_EXPORT',
            'Export AI Analysis',
            'AI_ANALYSIS',
            'EXPORT',
            'Export AI analysis results.',
            'HIGH',
            TRUE
        ),
        (
            'AI_ANALYSIS_DELETE',
            'Delete AI Analysis',
            'AI_ANALYSIS',
            'DELETE',
            'Delete an AI analysis record.',
            'CRITICAL',
            TRUE
        ),

        -- =====================================================
        -- REPORT MANAGEMENT
        -- =====================================================

        (
            'REPORT_VIEW',
            'View Reports',
            'REPORT',
            'VIEW',
            'View generated reports.',
            'LOW',
            FALSE
        ),
        (
            'REPORT_CREATE',
            'Create Report',
            'REPORT',
            'CREATE',
            'Create a new report.',
            'MEDIUM',
            FALSE
        ),
        (
            'REPORT_GENERATE',
            'Generate Report',
            'REPORT',
            'GENERATE',
            'Generate a report from platform data.',
            'MEDIUM',
            FALSE
        ),
        (
            'REPORT_UPDATE',
            'Update Report',
            'REPORT',
            'UPDATE',
            'Update report information.',
            'MEDIUM',
            FALSE
        ),
        (
            'REPORT_DELETE',
            'Delete Report',
            'REPORT',
            'DELETE',
            'Delete a report.',
            'HIGH',
            TRUE
        ),
        (
            'REPORT_APPROVE',
            'Approve Report',
            'REPORT',
            'APPROVE',
            'Approve a generated report.',
            'HIGH',
            TRUE
        ),
        (
            'REPORT_EXPORT',
            'Export Report',
            'REPORT',
            'EXPORT',
            'Export a report.',
            'HIGH',
            FALSE
        ),
        (
            'REPORT_PRINT',
            'Print Report',
            'REPORT',
            'PRINT',
            'Print a generated report.',
            'MEDIUM',
            FALSE
        ),
        (
            'REPORT_SHARE',
            'Share Report',
            'REPORT',
            'SHARE',
            'Share a report with authorized users.',
            'HIGH',
            TRUE
        ),

        -- =====================================================
        -- REPORT TEMPLATE MANAGEMENT
        -- =====================================================

        (
            'REPORT_TEMPLATE_VIEW',
            'View Report Templates',
            'REPORT_TEMPLATE',
            'VIEW',
            'View report templates.',
            'LOW',
            FALSE
        ),
        (
            'REPORT_TEMPLATE_CREATE',
            'Create Report Template',
            'REPORT_TEMPLATE',
            'CREATE',
            'Create a report template.',
            'MEDIUM',
            FALSE
        ),
        (
            'REPORT_TEMPLATE_UPDATE',
            'Update Report Template',
            'REPORT_TEMPLATE',
            'UPDATE',
            'Update a report template.',
            'MEDIUM',
            FALSE
        ),
        (
            'REPORT_TEMPLATE_DELETE',
            'Delete Report Template',
            'REPORT_TEMPLATE',
            'DELETE',
            'Delete a report template.',
            'HIGH',
            TRUE
        ),

        -- =====================================================
        -- SYSTEM SETTINGS
        -- =====================================================

        (
            'SYSTEM_SETTING_VIEW',
            'View System Settings',
            'SYSTEM_SETTING',
            'VIEW',
            'View system settings.',
            'MEDIUM',
            FALSE
        ),
        (
            'SYSTEM_SETTING_UPDATE',
            'Update System Settings',
            'SYSTEM_SETTING',
            'UPDATE',
            'Update system configuration.',
            'CRITICAL',
            TRUE
        ),
        (
            'SYSTEM_SETTING_VIEW_SENSITIVE',
            'View Sensitive Settings',
            'SYSTEM_SETTING',
            'VIEW_SENSITIVE',
            'View sensitive system settings.',
            'CRITICAL',
            TRUE
        ),
        (
            'SYSTEM_SETTING_UPDATE_SECURITY',
            'Update Security Settings',
            'SYSTEM_SETTING',
            'UPDATE_SECURITY',
            'Update platform security settings.',
            'CRITICAL',
            TRUE
        ),
        (
            'SYSTEM_SETTING_RESET',
            'Reset System Settings',
            'SYSTEM_SETTING',
            'RESET',
            'Reset system settings to default values.',
            'CRITICAL',
            TRUE
        ),

        -- =====================================================
        -- FEATURE FLAG MANAGEMENT
        -- =====================================================

        (
            'FEATURE_FLAG_VIEW',
            'View Feature Flags',
            'FEATURE_FLAG',
            'VIEW',
            'View feature flags.',
            'LOW',
            FALSE
        ),
        (
            'FEATURE_FLAG_CREATE',
            'Create Feature Flag',
            'FEATURE_FLAG',
            'CREATE',
            'Create a new feature flag.',
            'HIGH',
            FALSE
        ),
        (
            'FEATURE_FLAG_UPDATE',
            'Update Feature Flag',
            'FEATURE_FLAG',
            'UPDATE',
            'Update feature flag configuration.',
            'HIGH',
            FALSE
        ),
        (
            'FEATURE_FLAG_ENABLE',
            'Enable Feature Flag',
            'FEATURE_FLAG',
            'ENABLE',
            'Enable a platform feature.',
            'HIGH',
            TRUE
        ),
        (
            'FEATURE_FLAG_DISABLE',
            'Disable Feature Flag',
            'FEATURE_FLAG',
            'DISABLE',
            'Disable a platform feature.',
            'HIGH',
            TRUE
        ),
        (
            'FEATURE_FLAG_DELETE',
            'Delete Feature Flag',
            'FEATURE_FLAG',
            'DELETE',
            'Delete a feature flag.',
            'CRITICAL',
            TRUE
        ),

        -- =====================================================
        -- AUDIT LOG MANAGEMENT
        -- =====================================================

        (
            'AUDIT_LOG_VIEW',
            'View Audit Logs',
            'AUDIT_LOG',
            'VIEW',
            'View platform audit logs.',
            'HIGH',
            FALSE
        ),
        (
            'AUDIT_LOG_VIEW_SENSITIVE',
            'View Sensitive Audit Logs',
            'AUDIT_LOG',
            'VIEW_SENSITIVE',
            'View sensitive audit information.',
            'CRITICAL',
            TRUE
        ),
        (
            'AUDIT_LOG_EXPORT',
            'Export Audit Logs',
            'AUDIT_LOG',
            'EXPORT',
            'Export audit log information.',
            'CRITICAL',
            TRUE
        ),
        (
            'AUDIT_LOG_ARCHIVE',
            'Archive Audit Logs',
            'AUDIT_LOG',
            'ARCHIVE',
            'Archive historical audit logs.',
            'HIGH',
            TRUE
        ),
        (
            'AUDIT_LOG_VERIFY',
            'Verify Audit Log Integrity',
            'AUDIT_LOG',
            'VERIFY',
            'Verify audit log integrity.',
            'HIGH',
            FALSE
        ),

        -- =====================================================
        -- BACKUP AND RESTORE
        -- =====================================================

        (
            'BACKUP_VIEW',
            'View Backups',
            'BACKUP',
            'VIEW',
            'View database backup records.',
            'HIGH',
            FALSE
        ),
        (
            'BACKUP_CREATE',
            'Create Backup',
            'BACKUP',
            'CREATE',
            'Create an offline database backup.',
            'CRITICAL',
            TRUE
        ),
        (
            'BACKUP_DOWNLOAD',
            'Download Backup',
            'BACKUP',
            'DOWNLOAD',
            'Download a database backup.',
            'CRITICAL',
            TRUE
        ),
        (
            'BACKUP_RESTORE',
            'Restore Backup',
            'BACKUP',
            'RESTORE',
            'Restore the platform from a backup.',
            'CRITICAL',
            TRUE
        ),
        (
            'BACKUP_DELETE',
            'Delete Backup',
            'BACKUP',
            'DELETE',
            'Delete a database backup.',
            'CRITICAL',
            TRUE
        ),

        -- =====================================================
        -- OFFLINE SYNCHRONIZATION
        -- =====================================================

        (
            'SYNC_VIEW',
            'View Synchronization',
            'OFFLINE_SYNC',
            'VIEW',
            'View offline synchronization status.',
            'LOW',
            FALSE
        ),
        (
            'SYNC_EXECUTE',
            'Execute Synchronization',
            'OFFLINE_SYNC',
            'EXECUTE',
            'Execute an offline data synchronization.',
            'HIGH',
            FALSE
        ),
        (
            'SYNC_RETRY',
            'Retry Synchronization',
            'OFFLINE_SYNC',
            'RETRY',
            'Retry a failed synchronization.',
            'MEDIUM',
            FALSE
        ),
        (
            'SYNC_RESOLVE_CONFLICT',
            'Resolve Synchronization Conflict',
            'OFFLINE_SYNC',
            'RESOLVE_CONFLICT',
            'Resolve an offline synchronization conflict.',
            'HIGH',
            TRUE
        ),
        (
            'SYNC_CANCEL',
            'Cancel Synchronization',
            'OFFLINE_SYNC',
            'CANCEL',
            'Cancel an active synchronization.',
            'HIGH',
            FALSE
        )

    ) AS permission_data (
        permission_code,
        permission_name,
        module_name,
        action_name,
        description,
        risk_level,
        requires_approval
    )
)

INSERT INTO permissions (
    permission_code,
    permission_name,
    module_name,
    action_name,
    description,
    risk_level,
    requires_approval,
    status
)
SELECT
    permission_seed.permission_code,
    permission_seed.permission_name,
    permission_seed.module_name,
    permission_seed.action_name,
    permission_seed.description,
    permission_seed.risk_level,
    permission_seed.requires_approval,
    'ACTIVE'
FROM permission_seed
WHERE NOT EXISTS (
    SELECT 1
    FROM permissions existing_permission
    WHERE existing_permission.permission_code =
          permission_seed.permission_code
);

COMMIT;

-- ============================================================
-- VERIFICATION
-- ============================================================

SELECT
    module_name,
    COUNT(*) AS permission_count
FROM permissions
WHERE status = 'ACTIVE'
GROUP BY module_name
ORDER BY module_name;

SELECT
    id,
    permission_code,
    permission_name,
    module_name,
    action_name,
    risk_level,
    requires_approval,
    status
FROM permissions
ORDER BY module_name, permission_code;