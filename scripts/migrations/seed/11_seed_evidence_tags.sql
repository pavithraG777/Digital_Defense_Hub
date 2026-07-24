-- ============================================================
-- FILE NAME : 11_seed_evidence_tags.sql
-- PURPOSE   : Insert default evidence classification tags
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
-- Verify Super Admin user exists
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM users u
        JOIN organizations o
            ON o.id = u.organization_id
        WHERE o.organization_code = 'CSL001'
          AND u.username = 'superadmin'
          AND u.account_status = 'ACTIVE'
          AND u.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'Active Super Admin user does not exist. Run 06_seed_admin_user.sql first.';
    END IF;
END;
$$;

-- ============================================================
-- GENERAL TAGS
-- ============================================================

INSERT INTO evidence_tags (
    organization_id,
    tag_code,
    tag_name,
    description,
    tag_category,
    status,
    created_by,
    created_at,
    updated_at
)
SELECT
    o.id,
    tag_data.tag_code,
    tag_data.tag_name,
    tag_data.description,
    tag_data.tag_category,
    'ACTIVE',
    u.id,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM organizations o
JOIN users u
    ON u.organization_id = o.id
CROSS JOIN (
    VALUES
        (
            'CRITICAL_EVIDENCE',
            'Critical Evidence',
            'Evidence considered highly important for investigation and incident resolution.',
            'GENERAL'
        ),
        (
            'REQUIRES_REVIEW',
            'Requires Review',
            'Evidence that must be manually reviewed by an authorized analyst.',
            'GENERAL'
        ),
        (
            'VERIFIED',
            'Verified Evidence',
            'Evidence whose integrity and authenticity have been verified.',
            'GENERAL'
        ),
        (
            'UNVERIFIED',
            'Unverified Evidence',
            'Evidence that has not yet completed integrity or authenticity verification.',
            'GENERAL'
        ),
        (
            'SENSITIVE',
            'Sensitive Evidence',
            'Evidence containing confidential, private, or restricted information.',
            'GENERAL'
        ),
        (
            'HIGH_PRIORITY',
            'High Priority Evidence',
            'Evidence that requires immediate analysis or investigator attention.',
            'GENERAL'
        ),

-- ============================================================
-- MALWARE TAGS
-- ============================================================

        (
            'MALWARE_SAMPLE',
            'Malware Sample',
            'File or artifact suspected or confirmed to contain malicious software.',
            'MALWARE'
        ),
        (
            'TROJAN',
            'Trojan',
            'Evidence associated with Trojan-based malicious activity.',
            'MALWARE'
        ),
        (
            'SPYWARE',
            'Spyware',
            'Evidence related to software designed to monitor or steal information.',
            'MALWARE'
        ),
        (
            'ROOTKIT',
            'Rootkit',
            'Evidence associated with hidden privileged persistence mechanisms.',
            'MALWARE'
        ),
        (
            'SUSPICIOUS_EXECUTABLE',
            'Suspicious Executable',
            'Executable file requiring malware or behavioral analysis.',
            'MALWARE'
        ),

-- ============================================================
-- RANSOMWARE TAGS
-- ============================================================

        (
            'RANSOMWARE_SAMPLE',
            'Ransomware Sample',
            'Evidence suspected or confirmed to be associated with ransomware.',
            'RANSOMWARE'
        ),
        (
            'ENCRYPTED_FILE',
            'Encrypted File',
            'File encrypted or modified during a suspected ransomware incident.',
            'RANSOMWARE'
        ),
        (
            'RANSOM_NOTE',
            'Ransom Note',
            'Message or file containing ransom instructions or payment demands.',
            'RANSOMWARE'
        ),
        (
            'MASS_FILE_CHANGE',
            'Mass File Change',
            'Evidence showing rapid modification, renaming, or encryption of multiple files.',
            'RANSOMWARE'
        ),
        (
            'CANARY_TRIGGER',
            'Canary Trigger Evidence',
            'Evidence generated when a ransomware canary file was accessed or modified.',
            'RANSOMWARE'
        ),

-- ============================================================
-- PHISHING TAGS
-- ============================================================

        (
            'PHISHING_EMAIL',
            'Phishing Email',
            'Email suspected or confirmed to contain phishing content.',
            'PHISHING'
        ),
        (
            'MALICIOUS_LINK',
            'Malicious Link',
            'Suspicious or harmful URL found in an email, document, or message.',
            'PHISHING'
        ),
        (
            'FAKE_LOGIN_PAGE',
            'Fake Login Page',
            'Imitation login page designed to steal credentials.',
            'PHISHING'
        ),
        (
            'MALICIOUS_ATTACHMENT',
            'Malicious Attachment',
            'Email or message attachment suspected of containing harmful content.',
            'PHISHING'
        ),
        (
            'SPOOFED_SENDER',
            'Spoofed Sender',
            'Evidence showing sender identity, domain, or email address impersonation.',
            'PHISHING'
        ),

-- ============================================================
-- DEEPFAKE TAGS
-- ============================================================

        (
            'DEEPFAKE_IMAGE',
            'Deepfake Image',
            'Image suspected or confirmed to have been synthetically generated or manipulated.',
            'DEEPFAKE'
        ),
        (
            'DEEPFAKE_VIDEO',
            'Deepfake Video',
            'Video suspected or confirmed to contain manipulated facial or visual content.',
            'DEEPFAKE'
        ),
        (
            'SYNTHETIC_AUDIO',
            'Synthetic Audio',
            'Audio suspected or confirmed to have been artificially generated or cloned.',
            'DEEPFAKE'
        ),
        (
            'FACE_MANIPULATION',
            'Face Manipulation',
            'Evidence containing facial replacement, alteration, or synthetic reconstruction.',
            'DEEPFAKE'
        ),
        (
            'MEDIA_METADATA_MISMATCH',
            'Media Metadata Mismatch',
            'Media file containing inconsistent, altered, or suspicious metadata.',
            'DEEPFAKE'
        ),

-- ============================================================
-- INSIDER THREAT TAGS
-- ============================================================

        (
            'INSIDER_ACTIVITY',
            'Insider Activity',
            'Evidence connected to suspicious actions performed by an internal user.',
            'INSIDER_THREAT'
        ),
        (
            'UNAUTHORIZED_FILE_ACCESS',
            'Unauthorized File Access',
            'Evidence showing access to restricted files without proper authorization.',
            'INSIDER_THREAT'
        ),
        (
            'DATA_EXFILTRATION',
            'Data Exfiltration',
            'Evidence showing unauthorized copying or transfer of sensitive data.',
            'INSIDER_THREAT'
        ),
        (
            'PRIVILEGE_ABUSE',
            'Privilege Abuse',
            'Evidence of privileged permissions being used improperly.',
            'INSIDER_THREAT'
        ),
        (
            'POLICY_VIOLATION',
            'Policy Violation',
            'Evidence showing violation of organizational security policies.',
            'INSIDER_THREAT'
        ),

-- ============================================================
-- DATA BREACH TAGS
-- ============================================================

        (
            'EXPOSED_DATA',
            'Exposed Data',
            'Evidence containing information exposed to unauthorized parties.',
            'DATA_BREACH'
        ),
        (
            'PERSONAL_DATA',
            'Personal Data',
            'Evidence containing personally identifiable or personal information.',
            'DATA_BREACH'
        ),
        (
            'FINANCIAL_DATA',
            'Financial Data',
            'Evidence containing banking, payment, or financial information.',
            'DATA_BREACH'
        ),
        (
            'CREDENTIAL_LEAK',
            'Credential Leak',
            'Evidence containing exposed usernames, passwords, tokens, or secrets.',
            'DATA_BREACH'
        ),
        (
            'DATABASE_DUMP',
            'Database Dump',
            'Exported or copied database content requiring breach investigation.',
            'DATA_BREACH'
        ),

-- ============================================================
-- AUTHENTICATION TAGS
-- ============================================================

        (
            'FAILED_LOGIN',
            'Failed Login',
            'Evidence related to repeated or suspicious login failures.',
            'AUTHENTICATION'
        ),
        (
            'ACCOUNT_COMPROMISE',
            'Account Compromise',
            'Evidence suggesting unauthorized control of a user account.',
            'AUTHENTICATION'
        ),
        (
            'BRUTE_FORCE',
            'Brute Force',
            'Evidence showing repeated credential guessing attempts.',
            'AUTHENTICATION'
        ),
        (
            'PRIVILEGE_ESCALATION',
            'Privilege Escalation',
            'Evidence showing unauthorized elevation of permissions.',
            'AUTHENTICATION'
        ),
        (
            'MFA_BYPASS',
            'MFA Bypass',
            'Evidence suggesting circumvention of multi-factor authentication.',
            'AUTHENTICATION'
        ),

-- ============================================================
-- NETWORK TAGS
-- ============================================================

        (
            'SUSPICIOUS_NETWORK_TRAFFIC',
            'Suspicious Network Traffic',
            'Network activity requiring security investigation.',
            'NETWORK'
        ),
        (
            'MALICIOUS_IP',
            'Malicious IP Address',
            'Evidence associated with a suspicious or malicious IP address.',
            'NETWORK'
        ),
        (
            'COMMAND_AND_CONTROL',
            'Command and Control',
            'Traffic or artifact associated with a command-and-control server.',
            'NETWORK'
        ),
        (
            'PORT_SCAN',
            'Port Scan',
            'Evidence showing scanning or probing of network services.',
            'NETWORK'
        ),
        (
            'DNS_ANOMALY',
            'DNS Anomaly',
            'Evidence showing suspicious or abnormal DNS activity.',
            'NETWORK'
        ),

-- ============================================================
-- FORENSIC TAGS
-- ============================================================

        (
            'DISK_IMAGE',
            'Disk Image',
            'Forensic image created from a storage device.',
            'FORENSIC'
        ),
        (
            'MEMORY_DUMP',
            'Memory Dump',
            'Captured volatile memory used for forensic analysis.',
            'FORENSIC'
        ),
        (
            'LOG_FILE',
            'Log File',
            'System, application, security, or device log used as evidence.',
            'FORENSIC'
        ),
        (
            'DELETED_FILE',
            'Deleted File',
            'Recovered or referenced file that had previously been deleted.',
            'FORENSIC'
        ),
        (
            'TIMELINE_ARTIFACT',
            'Timeline Artifact',
            'Evidence used to reconstruct the sequence of incident events.',
            'FORENSIC'
        ),
        (
            'HASH_VERIFIED',
            'Hash Verified',
            'Evidence whose stored hash matches the calculated integrity hash.',
            'FORENSIC'
        ),

-- ============================================================
-- LEGAL TAGS
-- ============================================================

        (
            'LEGAL_HOLD',
            'Legal Hold',
            'Evidence that must be preserved for legal or regulatory purposes.',
            'LEGAL'
        ),
        (
            'CHAIN_OF_CUSTODY',
            'Chain of Custody',
            'Evidence requiring complete custody and handling documentation.',
            'LEGAL'
        ),
        (
            'COURT_ADMISSIBLE',
            'Court Admissible',
            'Evidence prepared according to legal admissibility requirements.',
            'LEGAL'
        ),
        (
            'REGULATORY_EVIDENCE',
            'Regulatory Evidence',
            'Evidence preserved for regulatory review or compliance reporting.',
            'LEGAL'
        ),
        (
            'RESTRICTED_ACCESS',
            'Restricted Access',
            'Evidence accessible only to specifically authorized users.',
            'LEGAL'
        )
) AS tag_data (
    tag_code,
    tag_name,
    description,
    tag_category
)
WHERE o.organization_code = 'CSL001'
  AND o.deleted_at IS NULL
  AND u.username = 'superadmin'
  AND u.deleted_at IS NULL
ON CONFLICT (organization_id, tag_code) DO NOTHING;

COMMIT;

-- ============================================================
-- VERIFICATION
-- ============================================================

SELECT
    et.tag_code,
    et.tag_name,
    et.tag_category,
    et.status,
    u.username AS created_by,
    et.created_at
FROM evidence_tags et
JOIN organizations o
    ON o.id = et.organization_id
LEFT JOIN users u
    ON u.id = et.created_by
WHERE o.organization_code = 'CSL001'
ORDER BY
    et.tag_category,
    et.tag_name;

-- ============================================================
-- COUNT VERIFICATION
-- ============================================================

SELECT
    et.tag_category,
    COUNT(*) AS total_tags
FROM evidence_tags et
JOIN organizations o
    ON o.id = et.organization_id
WHERE o.organization_code = 'CSL001'
GROUP BY et.tag_category
ORDER BY et.tag_category;