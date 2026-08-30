BEGIN;

ALTER TABLE ai_analysis_jobs
    DROP CONSTRAINT IF EXISTS ai_analysis_jobs_job_type_check;

ALTER TABLE ai_analysis_jobs
    ADD CONSTRAINT ai_analysis_jobs_job_type_check
    CHECK (job_type IN (
        'DEEPFAKE_IMAGE_DETECTION',
        'AI_GENERATED_IMAGE_DETECTION',
        'DEEPFAKE_VIDEO_DETECTION',
        'DEEPFAKE_AUDIO_DETECTION',
        'OCR_EXTRACTION',
        'IMAGE_FORENSICS',
        'VIDEO_FORENSICS',
        'AUDIO_FORENSICS',
        'MALWARE_DETECTION',
        'LOG_ANOMALY_DETECTION',
        'RANSOMWARE_DETECTION',
        'FILE_CLASSIFICATION',
        'METADATA_ANALYSIS',
        'RISK_SCORING',
        'CUSTOM'
    ));

COMMIT;
