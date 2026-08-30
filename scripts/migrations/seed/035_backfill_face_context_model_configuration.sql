UPDATE ai_model_versions AS model_version
SET configuration = COALESCE(model_version.configuration, '{}'::jsonb)
    || jsonb_build_object(
        'preprocessing', dataset.metadata->>'preprocessing',
        'face_context_analysis', true,
        'context_scale', COALESCE((dataset.metadata->>'context_scale')::numeric, 2.35),
        'input_width', COALESCE((dataset.metadata->>'image_size')::integer, 224),
        'input_height', COALESCE((dataset.metadata->>'image_size')::integer, 224)
    ),
    updated_at = CURRENT_TIMESTAMP
FROM ml_training_model_approvals AS approval
INNER JOIN ml_training_jobs AS training_job
    ON training_job.id = approval.training_job_id
INNER JOIN ml_training_dataset_versions AS dataset_version
    ON dataset_version.id = training_job.dataset_version_id
INNER JOIN ml_training_datasets AS dataset
    ON dataset.id = dataset_version.dataset_id
WHERE approval.ai_model_version_id = model_version.id
  AND approval.decision = 'APPROVED'
  AND COALESCE((dataset.metadata->>'face_context_analysis')::boolean, false) = true
  AND NULLIF(dataset.metadata->>'preprocessing', '') IS NOT NULL;
