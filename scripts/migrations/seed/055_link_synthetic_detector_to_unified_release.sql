-- The existing organization-trained synthetic-image detector remains active
-- alongside the copy-robust whole-image v4 specialist.  This label lets the
-- API/UI report both jobs as members of one logical release without merging
-- their incompatible neural-network weights.
UPDATE ai_model_versions AS v
SET configuration = COALESCE(v.configuration, '{}'::jsonb) || jsonb_build_object(
        'ensemble_role', 'SYNTHETIC_IMAGE',
        'ensemble_release', 'DDH_UNIFIED_IMAGE_ENSEMBLE_V1',
        'detects_ai_generated_images', true,
        'positive_class_semantics', 'AI_GENERATED',
        'negative_class_semantics', 'CAMERA_ORIGINAL'
    ),
    updated_at = CURRENT_TIMESTAMP
FROM ai_models AS m
WHERE m.id = v.ai_model_id
  AND m.input_type = 'IMAGE'
  AND v.status = 'ACTIVE'
  AND v.is_default = TRUE
  AND COALESCE(v.configuration->>'detector_scope', '') =
      'AI_GENERATED_IMAGE_DETECTION'
  AND COALESCE(v.configuration->>'artifact_verified_by', '') = 'training-worker';
