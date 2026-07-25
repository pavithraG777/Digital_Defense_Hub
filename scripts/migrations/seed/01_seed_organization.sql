-- ============================================================
-- FILE NAME  : 01_seed_organization.sql
-- PURPOSE    : Insert the default organization master records
-- PROJECT    : Offline-First Cyber Security and
--              Digital Forensics Platform
-- ============================================================

BEGIN;

INSERT INTO organizations (
    organization_code,
    legal_name,
    display_name,
    trade_name,
    organization_type,
    parent_organization_id,
    description,
    registration_number,
    registration_authority,
    registration_date,
    legal_structure,
    country_of_registration,
    registration_state,
    primary_email,
    secondary_email,
    primary_phone,
    emergency_phone,
    website_url,
    security_email,
    sector,
    industry,
    organization_size,
    employee_count,
    critical_infrastructure,
    data_sensitivity_level,
    deployment_mode,
    timezone,
    default_language,
    data_retention_days,
    logo_path,
    status
)
SELECT
    'CSL001',
    'Cyber Security Research and Digital Forensics Laboratory',
    'Cyber Security Lab',
    'CSL',
    'RESEARCH_EDUCATION',
    NULL,
    'Organization for offline cyber security monitoring, threat detection, incident management and digital forensic investigation.',
    NULL,
    NULL,
    NULL,
    'EDUCATIONAL_INSTITUTION',
    'India',
    'Tamil Nadu',
    'admin@cyberlab.local',
    NULL,
    '9876543210',
    NULL,
    NULL,
    'security@cyberlab.local',
    'EDUCATION',
    'CYBER_SECURITY_AND_DIGITAL_FORENSICS',
    'SMALL',
    50,
    FALSE,
    'CONFIDENTIAL',
    'OFFLINE',
    'Asia/Kolkata',
    'English',
    365,
    NULL,
    'ACTIVE'
WHERE NOT EXISTS (
    SELECT 1
    FROM organizations
    WHERE organization_code = 'CSL001'
);


INSERT INTO organizations (
    organization_code,
    legal_name,
    display_name,
    trade_name,
    organization_type,
    parent_organization_id,
    description,
    registration_number,
    registration_authority,
    registration_date,
    legal_structure,
    country_of_registration,
    registration_state,
    primary_email,
    secondary_email,
    primary_phone,
    emergency_phone,
    website_url,
    security_email,
    sector,
    industry,
    organization_size,
    employee_count,
    critical_infrastructure,
    data_sensitivity_level,
    deployment_mode,
    timezone,
    default_language,
    data_retention_days,
    logo_path,
    status
)
SELECT
    'BANK001',
    'Trust Bank Limited',
    'Trust Bank',
    'Trust',
    'FINANCIAL',
    NULL,
    'Banking organization for cybersecurity monitoring.',
    NULL,
    NULL,
    NULL,
    'PUBLIC_LIMITED',
    'India',
    'Tamil Nadu',
    'admin@trustbank.local',
    NULL,
    '9876543212',
    NULL,
    NULL,
    'security@trustbank.local',
    'FINANCIAL',
    'FINANCIAL_SERVICES',
    'LARGE',
    500,
    TRUE,
    'CONFIDENTIAL',
    'OFFLINE',
    'Asia/Kolkata',
    'English',
    365,
    NULL,
    'ACTIVE'
WHERE NOT EXISTS (
    SELECT 1
    FROM organizations
    WHERE organization_code = 'BANK001'
);

COMMIT;

-- Verify the inserted organizations
SELECT
    id,
    organization_code,
    legal_name,
    organization_type,
    organization_size,
    employee_count,
    critical_infrastructure,
    data_sensitivity_level,
    deployment_mode,
    status,
    created_at,
    updated_at
FROM organizations
WHERE organization_code IN (
    'CSL001',
    'BANK001'
)
ORDER BY organization_code;