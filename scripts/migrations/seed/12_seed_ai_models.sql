-- ============================================================
-- FILE NAME : 12_seed_ai_models.sql
-- PURPOSE   : Register default offline AI and forensic models
-- PROJECT   : Offline-First Cyber Security and
--             Digital Forensics Platform
-- ============================================================

BEGIN;

-- ============================================================
-- VERIFY ORGANIZATION
-- ============================================================

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

-- ============================================================
-- VERIFY SUPER ADMIN
-- ============================================================

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
          AND o.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'Active Super Admin user does not exist. Run 06_seed_admin_user.sql first.';
    END IF;
END;
$$;

-- ============================================================
-- INSERT DEFAULT AI MODELS
-- ============================================================

INSERT INTO ai_models (
    organization_id,
    model_code,
    model_name,
    description,
    model_type,
    framework,
    input_type,
    output_type,
    supports_offline_execution,
    supports_gpu,
    supports_cpu,
    minimum_memory_mb,
    maximum_file_size_bytes,
    status,
    created_by,
    created_at,
    updated_at
)
SELECT
    o.id,
    model_data.model_code,
    model_data.model_name,
    model_data.description,
    model_data.model_type,
    model_data.framework,
    model_data.input_type,
    model_data.output_type,
    model_data.supports_offline_execution,
    model_data.supports_gpu,
    model_data.supports_cpu,
    model_data.minimum_memory_mb,
    model_data.maximum_file_size_bytes,
    'DEVELOPMENT',
    u.id,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM organizations o
JOIN users u
    ON u.organization_id = o.id
CROSS JOIN (
    VALUES

        -- ----------------------------------------------------
        -- DEEPFAKE IMAGE DETECTION
        -- ----------------------------------------------------

        (
            'DFI001',
            'Offline Deepfake Image Detector',
            'Detects AI-generated and manipulated facial images using an offline deep learning model.',
            'DEEPFAKE_IMAGE_DETECTION',
            'PYTORCH',
            'IMAGE',
            'MULTIPLE_RESULTS',
            TRUE,
            TRUE,
            TRUE,
            2048,
            52428800
        ),

        -- ----------------------------------------------------
        -- DEEPFAKE VIDEO DETECTION
        -- ----------------------------------------------------

        (
            'DFV001',
            'Offline Deepfake Video Detector',
            'Extracts and analyses video frames to detect face swapping, synthetic content and temporal manipulation.',
            'DEEPFAKE_VIDEO_DETECTION',
            'PYTORCH',
            'VIDEO',
            'MULTIPLE_RESULTS',
            TRUE,
            TRUE,
            TRUE,
            4096,
            1073741824
        ),

        -- ----------------------------------------------------
        -- DEEPFAKE AUDIO DETECTION
        -- ----------------------------------------------------

        (
            'DFA001',
            'Offline Synthetic Audio Detector',
            'Analyses audio signals to identify voice cloning, synthetic speech and manipulated recordings.',
            'DEEPFAKE_AUDIO_DETECTION',
            'PYTORCH',
            'AUDIO',
            'CONFIDENCE_SCORE',
            TRUE,
            TRUE,
            TRUE,
            2048,
            524288000
        ),

        -- ----------------------------------------------------
        -- OCR EXTRACTION
        -- ----------------------------------------------------

        (
            'OCR001',
            'Offline Evidence OCR Extractor',
            'Extracts readable text from scanned evidence images and digital documents without internet connectivity.',
            'OCR_EXTRACTION',
            'OPENCV',
            'DOCUMENT',
            'TEXT_EXTRACTION',
            TRUE,
            FALSE,
            TRUE,
            1024,
            104857600
        ),

        -- ----------------------------------------------------
        -- IMAGE FORENSICS
        -- ----------------------------------------------------

        (
            'IMG001',
            'Digital Image Forensics Analyzer',
            'Examines image metadata, compression artefacts, noise patterns and possible image manipulation.',
            'IMAGE_FORENSICS',
            'OPENCV',
            'IMAGE',
            'MULTIPLE_RESULTS',
            TRUE,
            FALSE,
            TRUE,
            1024,
            104857600
        ),

        -- ----------------------------------------------------
        -- VIDEO FORENSICS
        -- ----------------------------------------------------

        (
            'VID001',
            'Digital Video Forensics Analyzer',
            'Examines video frames, metadata, encoding information and possible editing or manipulation indicators.',
            'VIDEO_FORENSICS',
            'OPENCV',
            'VIDEO',
            'MULTIPLE_RESULTS',
            TRUE,
            TRUE,
            TRUE,
            3072,
            2147483648
        ),

        -- ----------------------------------------------------
        -- AUDIO FORENSICS
        -- ----------------------------------------------------

        (
            'AUD001',
            'Digital Audio Forensics Analyzer',
            'Analyses audio metadata, waveform properties, silence gaps, splicing indicators and recording anomalies.',
            'AUDIO_FORENSICS',
            'CUSTOM',
            'AUDIO',
            'MULTIPLE_RESULTS',
            TRUE,
            FALSE,
            TRUE,
            1024,
            524288000
        ),

        -- ----------------------------------------------------
        -- MALWARE DETECTION
        -- ----------------------------------------------------

        (
            'MAL001',
            'Offline Static Malware Detector',
            'Classifies suspicious executable and binary files using extracted static file features.',
            'MALWARE_DETECTION',
            'SCIKIT_LEARN',
            'BINARY_FILE',
            'MULTIPLE_RESULTS',
            TRUE,
            FALSE,
            TRUE,
            1024,
            524288000
        ),

        -- ----------------------------------------------------
        -- LOG ANOMALY DETECTION
        -- ----------------------------------------------------

        (
            'LOG001',
            'Security Log Anomaly Detector',
            'Detects abnormal login activity, unusual system events and suspicious patterns in security logs.',
            'LOG_ANOMALY_DETECTION',
            'SCIKIT_LEARN',
            'LOG',
            'ANOMALY_SCORE',
            TRUE,
            FALSE,
            TRUE,
            1024,
            524288000
        ),

        -- ----------------------------------------------------
        -- RANSOMWARE DETECTION
        -- ----------------------------------------------------

        (
            'RAN001',
            'Offline Ransomware Behaviour Detector',
            'Detects ransomware indicators using file activity, extension changes and behavioural event patterns.',
            'RANSOMWARE_DETECTION',
            'PYTORCH',
            'LOG',
            'MULTIPLE_RESULTS',
            TRUE,
            TRUE,
            TRUE,
            2048,
            524288000
        ),

        -- ----------------------------------------------------
        -- FILE CLASSIFICATION
        -- ----------------------------------------------------

        (
            'FCL001',
            'Digital Evidence File Classifier',
            'Classifies collected evidence files according to their type, characteristics and investigation relevance.',
            'FILE_CLASSIFICATION',
            'SCIKIT_LEARN',
            'BINARY_FILE',
            'CLASSIFICATION',
            TRUE,
            FALSE,
            TRUE,
            512,
            524288000
        ),

        -- ----------------------------------------------------
        -- METADATA ANALYSIS
        -- ----------------------------------------------------

        (
            'MET001',
            'Evidence Metadata Analyzer',
            'Extracts and analyses metadata from images, videos, audio files and digital documents.',
            'METADATA_ANALYSIS',
            'CUSTOM',
            'METADATA',
            'MULTIPLE_RESULTS',
            TRUE,
            FALSE,
            TRUE,
            512,
            1073741824
        ),

        -- ----------------------------------------------------
        -- RISK SCORING
        -- ----------------------------------------------------

        (
            'RSK001',
            'Cyber Incident Risk Scoring Model',
            'Calculates incident risk using severity, affected assets, evidence findings and security alert information.',
            'RISK_SCORING',
            'SCIKIT_LEARN',
            'MULTIMODAL',
            'RISK_SCORE',
            TRUE,
            FALSE,
            TRUE,
            512,
            104857600
        )

) AS model_data (
    model_code,
    model_name,
    description,
    model_type,
    framework,
    input_type,
    output_type,
    supports_offline_execution,
    supports_gpu,
    supports_cpu,
    minimum_memory_mb,
    maximum_file_size_bytes
)
WHERE o.organization_code = 'CSL001'
  AND o.deleted_at IS NULL
  AND u.username = 'superadmin'
  AND u.account_status = 'ACTIVE'
  AND u.deleted_at IS NULL

  -- Prevent duplicate model codes and model names
  AND NOT EXISTS (
      SELECT 1
      FROM ai_models existing_model
      WHERE existing_model.organization_id = o.id
        AND (
            existing_model.model_code = model_data.model_code
            OR existing_model.model_name = model_data.model_name
        )
  );

COMMIT;

-- ============================================================
-- VERIFY INSERTED MODELS
-- ============================================================

SELECT
    am.model_code,
    am.model_name,
    am.model_type,
    am.framework,
    am.input_type,
    am.output_type,
    am.supports_offline_execution,
    am.supports_cpu,
    am.supports_gpu,
    am.minimum_memory_mb,
    am.maximum_file_size_bytes,
    am.status,
    u.username AS created_by
FROM ai_models am
JOIN organizations o
    ON o.id = am.organization_id
LEFT JOIN users u
    ON u.id = am.created_by
WHERE o.organization_code = 'CSL001'
  AND am.deleted_at IS NULL
ORDER BY am.model_code;

-- ============================================================
-- MODEL COUNT BY TYPE
-- ============================================================

SELECT
    am.model_type,
    COUNT(*) AS total_models
FROM ai_models am
JOIN organizations o
    ON o.id = am.organization_id
WHERE o.organization_code = 'CSL001'
  AND am.deleted_at IS NULL
GROUP BY am.model_type
ORDER BY am.model_type;

-- ============================================================
-- TOTAL MODEL COUNT
-- ============================================================

SELECT
    COUNT(*) AS total_ai_models
FROM ai_models am
JOIN organizations o
    ON o.id = am.organization_id
WHERE o.organization_code = 'CSL001'
  AND am.deleted_at IS NULL;