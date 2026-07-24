-- ============================================================
-- FILE NAME : 13_seed_ai_model_versions.sql
-- PART      : 1 OF 2
-- PURPOSE   : Register initial testing versions for AI models
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
-- VERIFY REQUIRED AI MODELS
-- ============================================================

DO $$
DECLARE
    missing_models TEXT;
BEGIN
    SELECT STRING_AGG(required_model.model_code, ', ')
    INTO missing_models
    FROM (
        VALUES
            ('DFI001'),
            ('DFV001'),
            ('DFA001'),
            ('OCR001'),
            ('IMG001'),
            ('VID001'),
            ('AUD001')
    ) AS required_model(model_code)
    WHERE NOT EXISTS (
        SELECT 1
        FROM ai_models am
        JOIN organizations o
            ON o.id = am.organization_id
        WHERE o.organization_code = 'CSL001'
          AND am.model_code = required_model.model_code
          AND am.deleted_at IS NULL
          AND o.deleted_at IS NULL
    );

    IF missing_models IS NOT NULL THEN
        RAISE EXCEPTION
            'Required AI models are missing: %. Run 12_seed_ai_models.sql first.',
            missing_models;
    END IF;
END;
$$;

-- ============================================================
-- IMPORTANT
-- ============================================================
-- These are registry placeholders for models that are still
-- under development/testing.
--
-- Actual model files, calculated SHA hashes, training datasets,
-- accuracy values and validation results must be updated after
-- the real AI models are trained or installed.
--
-- Therefore:
--     status      = TESTING
--     is_default  = FALSE
--     score fields remain NULL
-- ============================================================

INSERT INTO ai_model_versions (
    ai_model_id,
    version_number,
    version_name,
    model_file_path,
    model_file_hash,
    hash_algorithm,
    model_format,
    training_dataset_name,
    training_dataset_version,
    training_record_count,
    training_accuracy,
    validation_accuracy,
    precision_score,
    recall_score,
    f1_score,
    confidence_threshold,
    configuration,
    is_default,
    status,
    created_by,
    trained_at,
    validated_at,
    activated_at,
    created_at,
    updated_at
)
SELECT
    am.id,
    version_data.version_number,
    version_data.version_name,
    version_data.model_file_path,
    version_data.model_file_hash,
    'SHA256',
    version_data.model_format,
    version_data.training_dataset_name,
    version_data.training_dataset_version,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    version_data.confidence_threshold,
    version_data.configuration,
    FALSE,
    'TESTING',
    admin_user.id,
    NULL,
    NULL,
    NULL,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM organizations o
JOIN ai_models am
    ON am.organization_id = o.id
JOIN users admin_user
    ON admin_user.organization_id = o.id
JOIN (
    VALUES

        -- ====================================================
        -- 1. DEEPFAKE IMAGE DETECTION
        -- ====================================================

        (
            'DFI001',
            '1.0.0',
            'Initial Deepfake Image Detection Version',
            'models/deepfake/image/1.0.0/deepfake_image_detector.pth',
            repeat('0', 64),
            'PTH',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'device', 'auto',
                'image_width', 224,
                'image_height', 224,
                'batch_size', 1,
                'face_detection_enabled', true,
                'supported_extensions',
                    jsonb_build_array(
                        '.jpg',
                        '.jpeg',
                        '.png',
                        '.bmp',
                        '.webp'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 2. DEEPFAKE VIDEO DETECTION
        -- ====================================================

        (
            'DFV001',
            '1.0.0',
            'Initial Deepfake Video Detection Version',
            'models/deepfake/video/1.0.0/deepfake_video_detector.pth',
            repeat('0', 64),
            'PTH',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'device', 'auto',
                'frame_sampling_interval', 10,
                'maximum_frames', 300,
                'face_tracking_enabled', true,
                'temporal_analysis_enabled', true,
                'supported_extensions',
                    jsonb_build_array(
                        '.mp4',
                        '.avi',
                        '.mov',
                        '.mkv',
                        '.webm'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 3. DEEPFAKE AUDIO DETECTION
        -- ====================================================

        (
            'DFA001',
            '1.0.0',
            'Initial Synthetic Audio Detection Version',
            'models/deepfake/audio/1.0.0/synthetic_audio_detector.pth',
            repeat('0', 64),
            'PTH',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'device', 'auto',
                'sample_rate', 16000,
                'channel_mode', 'mono',
                'feature_type', 'mel_spectrogram',
                'segment_duration_seconds', 5,
                'supported_extensions',
                    jsonb_build_array(
                        '.wav',
                        '.mp3',
                        '.flac',
                        '.ogg',
                        '.m4a'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 4. OCR EXTRACTION
        -- ====================================================

        (
            'OCR001',
            '1.0.0',
            'Initial Offline Evidence OCR Version',
            'models/ocr/1.0.0/offline_ocr_pipeline.custom',
            repeat('0', 64),
            'CUSTOM',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'language', 'eng',
                'grayscale_enabled', true,
                'deskew_enabled', true,
                'noise_reduction_enabled', true,
                'automatic_rotation_enabled', true,
                'page_segmentation_mode', 3,
                'supported_extensions',
                    jsonb_build_array(
                        '.jpg',
                        '.jpeg',
                        '.png',
                        '.bmp',
                        '.tiff',
                        '.pdf'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 5. IMAGE FORENSICS
        -- ====================================================

        (
            'IMG001',
            '1.0.0',
            'Initial Digital Image Forensics Version',
            'models/forensics/image/1.0.0/image_forensics_pipeline.custom',
            repeat('0', 64),
            'CUSTOM',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'metadata_analysis_enabled', true,
                'error_level_analysis_enabled', true,
                'noise_analysis_enabled', true,
                'compression_analysis_enabled', true,
                'thumbnail_comparison_enabled', true,
                'supported_extensions',
                    jsonb_build_array(
                        '.jpg',
                        '.jpeg',
                        '.png',
                        '.bmp',
                        '.tiff',
                        '.webp'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 6. VIDEO FORENSICS
        -- ====================================================

        (
            'VID001',
            '1.0.0',
            'Initial Digital Video Forensics Version',
            'models/forensics/video/1.0.0/video_forensics_pipeline.custom',
            repeat('0', 64),
            'CUSTOM',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'metadata_analysis_enabled', true,
                'codec_analysis_enabled', true,
                'frame_extraction_enabled', true,
                'scene_change_detection_enabled', true,
                'duplicate_frame_detection_enabled', true,
                'audio_stream_analysis_enabled', true,
                'supported_extensions',
                    jsonb_build_array(
                        '.mp4',
                        '.avi',
                        '.mov',
                        '.mkv',
                        '.webm'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 7. AUDIO FORENSICS
        -- ====================================================

        (
            'AUD001',
            '1.0.0',
            'Initial Digital Audio Forensics Version',
            'models/forensics/audio/1.0.0/audio_forensics_pipeline.custom',
            repeat('0', 64),
            'CUSTOM',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'metadata_analysis_enabled', true,
                'waveform_analysis_enabled', true,
                'spectrogram_analysis_enabled', true,
                'silence_gap_detection_enabled', true,
                'audio_splice_detection_enabled', true,
                'channel_analysis_enabled', true,
                'supported_extensions',
                    jsonb_build_array(
                        '.wav',
                        '.mp3',
                        '.flac',
                        '.ogg',
                        '.m4a'
                    ),
                'placeholder_file', true
            )
        )

) AS version_data (
    model_code,
    version_number,
    version_name,
    model_file_path,
    model_file_hash,
    model_format,
    training_dataset_name,
    training_dataset_version,
    confidence_threshold,
    configuration
)
    ON version_data.model_code = am.model_code
WHERE o.organization_code = 'CSL001'
  AND o.deleted_at IS NULL
  AND am.deleted_at IS NULL
  AND admin_user.username = 'superadmin'
  AND admin_user.account_status = 'ACTIVE'
  AND admin_user.deleted_at IS NULL
ON CONFLICT (ai_model_id, version_number) DO NOTHING;

-- ============================================================
-- END OF PART 1
-- Do not add COMMIT here.
-- Part 2 continues the same transaction.
-- ============================================================

-- ============================================================
-- FILE NAME : 13_seed_ai_model_versions.sql
-- PART      : 2 OF 2
-- CONTINUES : Part 1 transaction
-- ============================================================

-- ============================================================
-- VERIFY REMAINING REQUIRED AI MODELS
-- ============================================================

DO $$
DECLARE
    missing_models TEXT;
BEGIN
    SELECT STRING_AGG(required_model.model_code, ', ')
    INTO missing_models
    FROM (
        VALUES
            ('MAL001'),
            ('LOG001'),
            ('RAN001'),
            ('FCL001'),
            ('MET001'),
            ('RSK001')
    ) AS required_model(model_code)
    WHERE NOT EXISTS (
        SELECT 1
        FROM ai_models am
        JOIN organizations o
            ON o.id = am.organization_id
        WHERE o.organization_code = 'CSL001'
          AND am.model_code = required_model.model_code
          AND am.deleted_at IS NULL
          AND o.deleted_at IS NULL
    );

    IF missing_models IS NOT NULL THEN
        RAISE EXCEPTION
            'Required AI models are missing: %. Run 12_seed_ai_models.sql first.',
            missing_models;
    END IF;
END;
$$;

-- ============================================================
-- INSERT REMAINING AI MODEL VERSIONS
-- ============================================================

INSERT INTO ai_model_versions (
    ai_model_id,
    version_number,
    version_name,
    model_file_path,
    model_file_hash,
    hash_algorithm,
    model_format,
    training_dataset_name,
    training_dataset_version,
    training_record_count,
    training_accuracy,
    validation_accuracy,
    precision_score,
    recall_score,
    f1_score,
    confidence_threshold,
    configuration,
    is_default,
    status,
    created_by,
    trained_at,
    validated_at,
    activated_at,
    created_at,
    updated_at
)
SELECT
    am.id,
    version_data.version_number,
    version_data.version_name,
    version_data.model_file_path,
    version_data.model_file_hash,
    'SHA256',
    version_data.model_format,
    version_data.training_dataset_name,
    version_data.training_dataset_version,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    version_data.confidence_threshold,
    version_data.configuration,
    FALSE,
    'TESTING',
    admin_user.id,
    NULL,
    NULL,
    NULL,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM organizations o
JOIN ai_models am
    ON am.organization_id = o.id
JOIN users admin_user
    ON admin_user.organization_id = o.id
JOIN (
    VALUES

        -- ====================================================
        -- 8. MALWARE DETECTION
        -- ====================================================

        (
            'MAL001',
            '1.0.0',
            'Initial Offline Malware Detection Version',
            'models/security/malware/1.0.0/static_malware_detector.joblib',
            repeat('0', 64),
            'JOBLIB',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'analysis_type', 'static',
                'extract_pe_features', true,
                'extract_file_entropy', true,
                'extract_import_table', true,
                'extract_section_information', true,
                'extract_string_features', true,
                'maximum_scan_timeout_seconds', 120,
                'supported_extensions',
                    jsonb_build_array(
                        '.exe',
                        '.dll',
                        '.sys',
                        '.bin',
                        '.msi',
                        '.scr'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 9. LOG ANOMALY DETECTION
        -- ====================================================

        (
            'LOG001',
            '1.0.0',
            'Initial Security Log Anomaly Detection Version',
            'models/security/log_anomaly/1.0.0/log_anomaly_detector.joblib',
            repeat('0', 64),
            'JOBLIB',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'analysis_window_minutes', 15,
                'minimum_event_count', 10,
                'detect_failed_logins', true,
                'detect_unusual_login_time', true,
                'detect_privilege_changes', true,
                'detect_repeated_access_denials', true,
                'detect_abnormal_event_frequency', true,
                'supported_log_formats',
                    jsonb_build_array(
                        'JSON',
                        'CSV',
                        'SYSLOG',
                        'WINDOWS_EVENT',
                        'PLAIN_TEXT'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 10. RANSOMWARE DETECTION
        -- ====================================================

        (
            'RAN001',
            '1.0.0',
            'Initial Offline Ransomware Behaviour Detection Version',
            'models/security/ransomware/1.0.0/ransomware_detector.pth',
            repeat('0', 64),
            'PTH',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'device', 'auto',
                'monitor_file_renames', true,
                'monitor_extension_changes', true,
                'monitor_entropy_changes', true,
                'monitor_mass_file_updates', true,
                'monitor_canary_files', true,
                'event_window_seconds', 60,
                'minimum_suspicious_events', 20,
                'automatic_isolation_enabled', false,
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 11. FILE CLASSIFICATION
        -- ====================================================

        (
            'FCL001',
            '1.0.0',
            'Initial Digital Evidence File Classification Version',
            'models/forensics/file_classification/1.0.0/file_classifier.joblib',
            repeat('0', 64),
            'JOBLIB',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'detect_file_type_from_signature', true,
                'detect_extension_mismatch', true,
                'extract_mime_type', true,
                'extract_entropy', true,
                'extract_basic_metadata', true,
                'classification_labels',
                    jsonb_build_array(
                        'IMAGE',
                        'VIDEO',
                        'AUDIO',
                        'DOCUMENT',
                        'ARCHIVE',
                        'EXECUTABLE',
                        'LOG',
                        'DATABASE',
                        'UNKNOWN'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 12. METADATA ANALYSIS
        -- ====================================================

        (
            'MET001',
            '1.0.0',
            'Initial Evidence Metadata Analysis Version',
            'models/forensics/metadata/1.0.0/metadata_analyzer.custom',
            repeat('0', 64),
            'CUSTOM',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'extract_file_system_metadata', true,
                'extract_image_exif', true,
                'extract_video_metadata', true,
                'extract_audio_metadata', true,
                'extract_document_properties', true,
                'detect_timestamp_anomalies', true,
                'detect_metadata_mismatch', true,
                'preserve_original_values', true,
                'supported_categories',
                    jsonb_build_array(
                        'IMAGE',
                        'VIDEO',
                        'AUDIO',
                        'DOCUMENT',
                        'BINARY_FILE'
                    ),
                'placeholder_file', true
            )
        ),

        -- ====================================================
        -- 13. RISK SCORING
        -- ====================================================

        (
            'RSK001',
            '1.0.0',
            'Initial Cyber Incident Risk Scoring Version',
            'models/security/risk_scoring/1.0.0/incident_risk_model.joblib',
            repeat('0', 64),
            'JOBLIB',
            NULL,
            NULL,
            50.00::NUMERIC,
            jsonb_build_object(
                'deployment_mode', 'offline',
                'score_range_minimum', 0,
                'score_range_maximum', 100,
                'severity_weight', 0.25,
                'priority_weight', 0.15,
                'affected_asset_weight', 0.15,
                'data_exposure_weight', 0.15,
                'ransomware_weight', 0.15,
                'evidence_findings_weight', 0.10,
                'alert_confidence_weight', 0.05,
                'risk_levels',
                    jsonb_build_object(
                        'LOW', jsonb_build_array(0, 24),
                        'MEDIUM', jsonb_build_array(25, 49),
                        'HIGH', jsonb_build_array(50, 74),
                        'CRITICAL', jsonb_build_array(75, 100)
                    ),
                'placeholder_file', true
            )
        )

) AS version_data (
    model_code,
    version_number,
    version_name,
    model_file_path,
    model_file_hash,
    model_format,
    training_dataset_name,
    training_dataset_version,
    confidence_threshold,
    configuration
)
    ON version_data.model_code = am.model_code
WHERE o.organization_code = 'CSL001'
  AND o.deleted_at IS NULL
  AND am.deleted_at IS NULL
  AND admin_user.username = 'superadmin'
  AND admin_user.account_status = 'ACTIVE'
  AND admin_user.deleted_at IS NULL
ON CONFLICT (ai_model_id, version_number) DO NOTHING;

COMMIT;

-- ============================================================
-- VERIFY ALL MODEL VERSIONS
-- ============================================================

SELECT
    am.model_code,
    am.model_name,
    amv.version_number,
    amv.version_name,
    amv.model_format,
    amv.model_file_path,
    amv.hash_algorithm,
    amv.confidence_threshold,
    amv.is_default,
    amv.status,
    u.username AS created_by,
    amv.created_at
FROM ai_model_versions amv
JOIN ai_models am
    ON am.id = amv.ai_model_id
JOIN organizations o
    ON o.id = am.organization_id
LEFT JOIN users u
    ON u.id = amv.created_by
WHERE o.organization_code = 'CSL001'
  AND am.deleted_at IS NULL
ORDER BY am.model_code, amv.version_number;

-- ============================================================
-- VERIFY MODEL VERSION COUNT
-- ============================================================

SELECT
    COUNT(*) AS total_model_versions
FROM ai_model_versions amv
JOIN ai_models am
    ON am.id = amv.ai_model_id
JOIN organizations o
    ON o.id = am.organization_id
WHERE o.organization_code = 'CSL001'
  AND am.deleted_at IS NULL;

-- Expected count after Part 1 and Part 2:
-- 13

-- ============================================================
-- VERIFY VERSION STATUS COUNT
-- ============================================================

SELECT
    amv.status,
    COUNT(*) AS total_versions
FROM ai_model_versions amv
JOIN ai_models am
    ON am.id = amv.ai_model_id
JOIN organizations o
    ON o.id = am.organization_id
WHERE o.organization_code = 'CSL001'
  AND am.deleted_at IS NULL
GROUP BY amv.status
ORDER BY amv.status;

-- ============================================================
-- VERIFY MODELS WITHOUT A VERSION
-- ============================================================

SELECT
    am.model_code,
    am.model_name
FROM ai_models am
JOIN organizations o
    ON o.id = am.organization_id
LEFT JOIN ai_model_versions amv
    ON amv.ai_model_id = am.id
WHERE o.organization_code = 'CSL001'
  AND am.deleted_at IS NULL
  AND amv.id IS NULL
ORDER BY am.model_code;

-- Expected result:
-- No rows

-- ============================================================
-- END OF 13_seed_ai_model_versions.sql
-- ============================================================