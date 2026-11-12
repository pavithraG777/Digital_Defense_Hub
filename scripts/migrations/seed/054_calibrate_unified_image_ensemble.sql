-- Calibrate the verified Colab specialists and expose them as one auditable
-- DDH image ensemble release.  Historical versions remain registered for
-- rollback, but only each model's active default participates in inference.
UPDATE ai_model_versions AS v
SET confidence_threshold = 59.00,
    validation_accuracy = GREATEST(COALESCE(v.validation_accuracy, 0), 93.00),
    configuration = COALESCE(v.configuration, '{}'::jsonb) || jsonb_build_object(
        'ensemble_role', 'WHOLE_IMAGE_AI',
        'preprocessing', 'WHOLE_IMAGE_RGB_COPY_ROBUST_V2',
        'calibrated_decision_threshold', true,
        'model_probability_weight', 1.0,
        'ensemble_release', 'DDH_UNIFIED_IMAGE_ENSEMBLE_V1',
        'detects_ai_generated_images', true,
        'copy_robust', true
    ),
    updated_at = CURRENT_TIMESTAMP
FROM ai_models AS m
WHERE m.id = v.ai_model_id
  AND m.model_code = 'DDH_WHOLE_IMAGE_AI_V2'
  AND v.version_number = '4.0.0';

UPDATE ai_model_versions AS v
SET confidence_threshold = 53.00,
    validation_accuracy = GREATEST(COALESCE(v.validation_accuracy, 0), 86.28),
    configuration = COALESCE(v.configuration, '{}'::jsonb) || jsonb_build_object(
        'ensemble_role', 'FACE_SWAP',
        'preprocessing', 'FACE_CONTEXT_CROP_V1',
        'context_scale', 2.35,
        'calibrated_decision_threshold', true,
        'model_probability_weight', 1.0,
        'ensemble_release', 'DDH_UNIFIED_IMAGE_ENSEMBLE_V1'
    ),
    updated_at = CURRENT_TIMESTAMP
FROM ai_models AS m
WHERE m.id = v.ai_model_id
  AND m.model_code = 'DDH_FACE_SWAP_V2'
  AND v.version_number = '2.0.1';

-- Keep the strongest existing organization-trained general detector in the
-- same logical release.  The repository still enforces completed training and
-- a minimum record count before it can execute.
UPDATE ai_model_versions AS v
SET configuration = COALESCE(v.configuration, '{}'::jsonb) || jsonb_build_object(
        'ensemble_role', 'GENERAL_DEEPFAKE',
        'ensemble_release', 'DDH_UNIFIED_IMAGE_ENSEMBLE_V1'
    ),
    updated_at = CURRENT_TIMESTAMP
FROM ai_models AS m
WHERE m.id = v.ai_model_id
  AND m.input_type = 'IMAGE'
  AND v.status = 'ACTIVE'
  AND v.is_default = TRUE
  AND COALESCE(v.configuration->>'artifact_verified_by', '') = 'training-worker'
  AND COALESCE(v.configuration->>'detector_scope', 'DEEPFAKE_IMAGE_DETECTION') =
      'DEEPFAKE_IMAGE_DETECTION';
