BEGIN;

CREATE TABLE media_analysis_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    asset_sequence BIGSERIAL NOT NULL UNIQUE,
    asset_code VARCHAR(100) NOT NULL,

    organization_id UUID NOT NULL,
    department_id UUID,
    incident_id UUID,

    evidence_id UUID,
    evidence_file_id UUID,

    original_file_name VARCHAR(255) NOT NULL,
    stored_file_name VARCHAR(255) NOT NULL,
    storage_path TEXT NOT NULL,

    media_type VARCHAR(30) NOT NULL,
    mime_type VARCHAR(150) NOT NULL,
    file_extension VARCHAR(30),
    file_size_bytes BIGINT NOT NULL,

    file_hash VARCHAR(64) NOT NULL,
    hash_algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA256',

    is_encrypted BOOLEAN NOT NULL DEFAULT true,
    encryption_algorithm VARCHAR(50),

    source_type VARCHAR(40) NOT NULL DEFAULT 'DIRECT_UPLOAD',
    status VARCHAR(30) NOT NULL DEFAULT 'AVAILABLE',

    uploaded_by UUID,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    uploaded_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    analyzed_at TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITHOUT TIME ZONE,

    CONSTRAINT fk_media_asset_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_media_asset_department
        FOREIGN KEY (department_id)
        REFERENCES departments(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_media_asset_incident
        FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_media_asset_evidence
        FOREIGN KEY (evidence_id)
        REFERENCES evidence_items(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_media_asset_evidence_file
        FOREIGN KEY (evidence_file_id)
        REFERENCES evidence_files(id)
        ON DELETE SET NULL,

    CONSTRAINT fk_media_asset_uploaded_by
        FOREIGN KEY (uploaded_by)
        REFERENCES users(id)
        ON DELETE SET NULL,

    CONSTRAINT chk_media_asset_type
        CHECK (
            media_type IN (
                'IMAGE',
                'VIDEO',
                'AUDIO',
                'DOCUMENT'
            )
        ),

    CONSTRAINT chk_media_asset_source
        CHECK (
            source_type IN (
                'DIRECT_UPLOAD',
                'EVIDENCE_IMPORT',
                'INCIDENT_IMPORT',
                'API_IMPORT'
            )
        ),

    CONSTRAINT chk_media_asset_status
        CHECK (
            status IN (
                'UPLOADING',
                'AVAILABLE',
                'PROCESSING',
                'ANALYZED',
                'FAILED',
                'QUARANTINED',
                'ARCHIVED',
                'DELETED'
            )
        ),

    CONSTRAINT chk_media_asset_size
        CHECK (file_size_bytes >= 0),

    CONSTRAINT chk_media_asset_hash
        CHECK (
            file_hash ~ '^[0-9A-Fa-f]{64}$'
        ),

    CONSTRAINT chk_media_asset_hash_algorithm
        CHECK (hash_algorithm = 'SHA256'),

    CONSTRAINT chk_media_asset_encryption
        CHECK (
            is_encrypted = false
            OR encryption_algorithm IS NOT NULL
        ),

    CONSTRAINT chk_media_asset_evidence_link
        CHECK (
            evidence_file_id IS NULL
            OR evidence_id IS NOT NULL
        ),

    CONSTRAINT uq_media_asset_code
        UNIQUE (organization_id, asset_code),

    CONSTRAINT uq_media_asset_storage_path
        UNIQUE (organization_id, storage_path),

    CONSTRAINT uq_media_asset_org_id
        UNIQUE (organization_id, id)
);

CREATE INDEX idx_media_assets_organization
    ON media_analysis_assets (
        organization_id,
        created_at DESC
    );

CREATE INDEX idx_media_assets_department
    ON media_analysis_assets (department_id);

CREATE INDEX idx_media_assets_incident
    ON media_analysis_assets (incident_id);

CREATE INDEX idx_media_assets_evidence
    ON media_analysis_assets (evidence_id);

CREATE INDEX idx_media_assets_type
    ON media_analysis_assets (
        organization_id,
        media_type,
        created_at DESC
    );

CREATE INDEX idx_media_assets_status
    ON media_analysis_assets (
        organization_id,
        status,
        created_at DESC
    );

CREATE INDEX idx_media_assets_hash
    ON media_analysis_assets (
        organization_id,
        file_hash
    );

ALTER TABLE ai_analysis_jobs
    ADD COLUMN media_asset_id UUID;

ALTER TABLE ai_analysis_jobs
    ALTER COLUMN evidence_id DROP NOT NULL;

ALTER TABLE ai_analysis_jobs
    ADD CONSTRAINT uq_ai_analysis_job_org_id
        UNIQUE (organization_id, id);

ALTER TABLE ai_analysis_jobs
    ADD CONSTRAINT fk_ai_job_media_asset
        FOREIGN KEY (
            organization_id,
            media_asset_id
        )
        REFERENCES media_analysis_assets (
            organization_id,
            id
        )
        ON DELETE CASCADE;

ALTER TABLE ai_analysis_jobs
    ADD CONSTRAINT chk_ai_job_source
        CHECK (
            media_asset_id IS NOT NULL
            OR evidence_id IS NOT NULL
        );

CREATE INDEX idx_ai_jobs_media_asset
    ON ai_analysis_jobs (media_asset_id);

CREATE INDEX idx_ai_jobs_organization_queue
    ON ai_analysis_jobs (
        organization_id,
        status,
        priority,
        created_at
    );

ALTER TABLE deepfake_detection_results
    ADD COLUMN organization_id UUID;

ALTER TABLE deepfake_detection_results
    ADD COLUMN media_asset_id UUID;

UPDATE deepfake_detection_results result
SET
    organization_id = job.organization_id,
    media_asset_id = job.media_asset_id
FROM ai_analysis_jobs job
WHERE job.id = result.analysis_job_id;

ALTER TABLE deepfake_detection_results
    ALTER COLUMN organization_id SET NOT NULL;

ALTER TABLE deepfake_detection_results
    ALTER COLUMN evidence_id DROP NOT NULL;

ALTER TABLE deepfake_detection_results
    ADD CONSTRAINT fk_deepfake_result_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE;

ALTER TABLE deepfake_detection_results
    ADD CONSTRAINT fk_deepfake_result_org_job
        FOREIGN KEY (
            organization_id,
            analysis_job_id
        )
        REFERENCES ai_analysis_jobs (
            organization_id,
            id
        )
        ON DELETE CASCADE;

ALTER TABLE deepfake_detection_results
    ADD CONSTRAINT fk_deepfake_result_media_asset
        FOREIGN KEY (
            organization_id,
            media_asset_id
        )
        REFERENCES media_analysis_assets (
            organization_id,
            id
        )
        ON DELETE CASCADE;

ALTER TABLE deepfake_detection_results
    ADD CONSTRAINT chk_deepfake_result_source
        CHECK (
            media_asset_id IS NOT NULL
            OR evidence_id IS NOT NULL
        );

CREATE INDEX idx_deepfake_results_organization
    ON deepfake_detection_results (
        organization_id,
        created_at DESC
    );

CREATE INDEX idx_deepfake_results_media_asset
    ON deepfake_detection_results (media_asset_id);

ALTER TABLE media_forensics_results
    ADD COLUMN organization_id UUID;

ALTER TABLE media_forensics_results
    ADD COLUMN media_asset_id UUID;

UPDATE media_forensics_results result
SET
    organization_id = job.organization_id,
    media_asset_id = job.media_asset_id
FROM ai_analysis_jobs job
WHERE job.id = result.analysis_job_id;

ALTER TABLE media_forensics_results
    ALTER COLUMN organization_id SET NOT NULL;

ALTER TABLE media_forensics_results
    ALTER COLUMN evidence_id DROP NOT NULL;

ALTER TABLE media_forensics_results
    ADD CONSTRAINT fk_media_forensics_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE;

ALTER TABLE media_forensics_results
    ADD CONSTRAINT fk_media_forensics_org_job
        FOREIGN KEY (
            organization_id,
            analysis_job_id
        )
        REFERENCES ai_analysis_jobs (
            organization_id,
            id
        )
        ON DELETE CASCADE;

ALTER TABLE media_forensics_results
    ADD CONSTRAINT fk_media_forensics_media_asset
        FOREIGN KEY (
            organization_id,
            media_asset_id
        )
        REFERENCES media_analysis_assets (
            organization_id,
            id
        )
        ON DELETE CASCADE;

ALTER TABLE media_forensics_results
    ADD CONSTRAINT chk_media_forensics_source
        CHECK (
            media_asset_id IS NOT NULL
            OR evidence_id IS NOT NULL
        );

CREATE INDEX idx_media_forensics_organization
    ON media_forensics_results (
        organization_id,
        created_at DESC
    );

CREATE INDEX idx_media_forensics_media_asset
    ON media_forensics_results (media_asset_id);

ALTER TABLE evidence_analysis
    ADD COLUMN organization_id UUID;

ALTER TABLE evidence_analysis
    ADD COLUMN analysis_job_id UUID;

ALTER TABLE evidence_analysis
    ADD COLUMN media_asset_id UUID;

UPDATE evidence_analysis analysis
SET organization_id = evidence.organization_id
FROM evidence_items evidence
WHERE evidence.id = analysis.evidence_id;

ALTER TABLE evidence_analysis
    ALTER COLUMN organization_id SET NOT NULL;

ALTER TABLE evidence_analysis
    ALTER COLUMN evidence_id DROP NOT NULL;

ALTER TABLE evidence_analysis
    ADD CONSTRAINT fk_evidence_analysis_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE;

ALTER TABLE evidence_analysis
    ADD CONSTRAINT fk_evidence_analysis_org_job
        FOREIGN KEY (
            organization_id,
            analysis_job_id
        )
        REFERENCES ai_analysis_jobs (
            organization_id,
            id
        )
        ON DELETE CASCADE;

ALTER TABLE evidence_analysis
    ADD CONSTRAINT fk_evidence_analysis_media_asset
        FOREIGN KEY (
            organization_id,
            media_asset_id
        )
        REFERENCES media_analysis_assets (
            organization_id,
            id
        )
        ON DELETE CASCADE;

ALTER TABLE evidence_analysis
    ADD CONSTRAINT chk_evidence_analysis_source
        CHECK (
            media_asset_id IS NOT NULL
            OR evidence_id IS NOT NULL
        );

CREATE UNIQUE INDEX uq_evidence_analysis_job
    ON evidence_analysis (analysis_job_id)
    WHERE analysis_job_id IS NOT NULL;

CREATE INDEX idx_evidence_analysis_organization
    ON evidence_analysis (
        organization_id,
        created_at DESC
    );

CREATE INDEX idx_evidence_analysis_media_asset
    ON evidence_analysis (media_asset_id);

ALTER TABLE ocr_results
    ADD COLUMN organization_id UUID;

ALTER TABLE ocr_results
    ADD COLUMN media_asset_id UUID;

ALTER TABLE ocr_results
    ADD COLUMN source_media_type VARCHAR(30);

ALTER TABLE ocr_results
    ADD COLUMN extraction_result VARCHAR(30)
        NOT NULL DEFAULT 'INCONCLUSIVE';

ALTER TABLE ocr_results
    ADD COLUMN engine_version VARCHAR(50);

ALTER TABLE ocr_results
    ADD COLUMN preprocessing_data JSONB
        NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE ocr_results
    ADD COLUMN metadata JSONB
        NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE ocr_results
    ADD COLUMN output_file_path TEXT;

UPDATE ocr_results result
SET
    organization_id = job.organization_id,
    media_asset_id = job.media_asset_id
FROM ai_analysis_jobs job
WHERE job.id = result.analysis_job_id;

UPDATE ocr_results result
SET source_media_type = asset.media_type
FROM media_analysis_assets asset
WHERE asset.id = result.media_asset_id
  AND asset.organization_id =
      result.organization_id;

UPDATE ocr_results result
SET source_media_type =
    CASE evidence.evidence_type
        WHEN 'IMAGE' THEN 'IMAGE'
        WHEN 'SCREENSHOT' THEN 'IMAGE'
        WHEN 'VIDEO' THEN 'VIDEO'
        WHEN 'DOCUMENT' THEN 'DOCUMENT'
        ELSE 'DOCUMENT'
    END
FROM evidence_items evidence
WHERE result.source_media_type IS NULL
  AND evidence.id = result.evidence_id;

UPDATE ocr_results
SET source_media_type = 'DOCUMENT'
WHERE source_media_type IS NULL;

UPDATE ocr_results
SET extraction_result =
    CASE
        WHEN extracted_text IS NULL
          OR BTRIM(extracted_text) = ''
            THEN 'NO_TEXT'
        ELSE 'TEXT_FOUND'
    END;

ALTER TABLE ocr_results
    ALTER COLUMN organization_id SET NOT NULL;

ALTER TABLE ocr_results
    ALTER COLUMN source_media_type SET NOT NULL;

ALTER TABLE ocr_results
    ALTER COLUMN evidence_id DROP NOT NULL;

ALTER TABLE ocr_results
    ADD CONSTRAINT fk_ocr_result_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE;

ALTER TABLE ocr_results
    ADD CONSTRAINT fk_ocr_result_org_job
        FOREIGN KEY (
            organization_id,
            analysis_job_id
        )
        REFERENCES ai_analysis_jobs (
            organization_id,
            id
        )
        ON DELETE CASCADE;

ALTER TABLE ocr_results
    ADD CONSTRAINT fk_ocr_result_media_asset
        FOREIGN KEY (
            organization_id,
            media_asset_id
        )
        REFERENCES media_analysis_assets (
            organization_id,
            id
        )
        ON DELETE CASCADE;

ALTER TABLE ocr_results
    ADD CONSTRAINT chk_ocr_result_source
        CHECK (
            media_asset_id IS NOT NULL
            OR evidence_id IS NOT NULL
        );

ALTER TABLE ocr_results
    ADD CONSTRAINT chk_ocr_source_media_type
        CHECK (
            source_media_type IN (
                'IMAGE',
                'VIDEO',
                'DOCUMENT'
            )
        );

ALTER TABLE ocr_results
    ADD CONSTRAINT chk_ocr_extraction_result
        CHECK (
            extraction_result IN (
                'TEXT_FOUND',
                'NO_TEXT',
                'PARTIAL',
                'INCONCLUSIVE',
                'ERROR'
            )
        );

CREATE INDEX idx_ocr_results_organization
    ON ocr_results (
        organization_id,
        created_at DESC
    );

CREATE INDEX idx_ocr_results_media_asset
    ON ocr_results (media_asset_id);

CREATE INDEX idx_ocr_results_extraction
    ON ocr_results (extraction_result);

COMMIT;
