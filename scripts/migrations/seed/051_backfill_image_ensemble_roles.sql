-- Give approved training checkpoints an explicit inference role. This does not
-- merge incompatible neural-network weights; the runtime combines the active
-- default detector for each compatible scope as an auditable ensemble.
UPDATE ai_model_versions
SET configuration = COALESCE(configuration, '{}'::jsonb) || jsonb_build_object(
    'ensemble_role',
    CASE
        WHEN configuration->>'detector_scope' = 'AI_GENERATED_IMAGE_DETECTION'
            THEN 'SYNTHETIC_IMAGE'
        ELSE 'GENERAL_DEEPFAKE'
    END
)
WHERE status = 'ACTIVE'
  AND is_default = TRUE
  AND configuration->>'artifact_verified_by' = 'training-worker'
  AND COALESCE(configuration->>'ensemble_role', '') = '';
