-- Ensure permissions introduced after the original catalogue seed exist in
-- already-provisioned databases as well as new installations.
BEGIN;

INSERT INTO permissions (
    permission_code, permission_name, module_name, action_name,
    description, risk_level, requires_approval, status
)
VALUES
    ('CANARY_FILE_VIEW', 'View Canary Files', 'CANARY_FILE', 'VIEW', 'View canary file records.', 'MEDIUM', FALSE, 'ACTIVE'),
    ('CANARY_FILE_CREATE', 'Create Canary File', 'CANARY_FILE', 'CREATE', 'Create a new canary file.', 'HIGH', FALSE, 'ACTIVE'),
    ('CANARY_FILE_UPDATE', 'Update Canary File', 'CANARY_FILE', 'UPDATE', 'Update canary file configuration.', 'HIGH', FALSE, 'ACTIVE'),
    ('CANARY_FILE_DELETE', 'Delete Canary File', 'CANARY_FILE', 'DELETE', 'Delete a canary file.', 'HIGH', TRUE, 'ACTIVE'),
    ('CANARY_FILE_DEPLOY', 'Deploy Canary File', 'CANARY_FILE', 'DEPLOY', 'Deploy a canary file to a monitored system.', 'HIGH', FALSE, 'ACTIVE'),
    ('CANARY_FILE_VERIFY', 'Verify Canary File', 'CANARY_FILE', 'VERIFY', 'Verify canary file integrity.', 'MEDIUM', FALSE, 'ACTIVE'),
    ('CANARY_FILE_VIEW_EVENTS', 'View Canary File Events', 'CANARY_FILE', 'VIEW_EVENTS', 'View canary file access and modification events.', 'HIGH', FALSE, 'ACTIVE'),
    ('CANARY_FILE_REGENERATE', 'Regenerate Canary File', 'CANARY_FILE', 'REGENERATE', 'Generate a replacement canary file.', 'HIGH', TRUE, 'ACTIVE'),
    ('IMAGE_ANALYSIS_VIEW', 'View Image Analyses', 'IMAGE_ANALYSIS', 'VIEW', 'View image-analysis records and results.', 'MEDIUM', FALSE, 'ACTIVE'),
    ('IMAGE_ANALYSIS_CREATE', 'Create Image Analysis', 'IMAGE_ANALYSIS', 'CREATE', 'Upload an image and start an analysis.', 'MEDIUM', FALSE, 'ACTIVE'),
    ('IMAGE_ANALYSIS_RUN', 'Run Image Analysis', 'IMAGE_ANALYSIS', 'RUN', 'Run image forensic and deepfake analysis.', 'HIGH', FALSE, 'ACTIVE'),
    ('IMAGE_ANALYSIS_VIEW_RESULTS', 'View Image Analysis Results', 'IMAGE_ANALYSIS', 'VIEW_RESULTS', 'View detailed image-analysis findings.', 'MEDIUM', FALSE, 'ACTIVE'),
    ('IMAGE_ANALYSIS_EXPORT', 'Export Image Analysis', 'IMAGE_ANALYSIS', 'EXPORT', 'Export image-analysis findings.', 'HIGH', TRUE, 'ACTIVE'),
    ('IMAGE_ANALYSIS_DELETE', 'Delete Image Analysis', 'IMAGE_ANALYSIS', 'DELETE', 'Delete an image-analysis record.', 'HIGH', TRUE, 'ACTIVE')
ON CONFLICT (permission_code) DO UPDATE SET
    permission_name = EXCLUDED.permission_name,
    module_name = EXCLUDED.module_name,
    action_name = EXCLUDED.action_name,
    description = EXCLUDED.description,
    risk_level = EXCLUDED.risk_level,
    requires_approval = EXCLUDED.requires_approval;

COMMIT;
