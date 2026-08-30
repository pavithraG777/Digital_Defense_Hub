package deepfakeforensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	analysisModelStatusActive      = "ACTIVE"
	analysisModelStatusDevelopment = "DEVELOPMENT"

	analysisModelVersionStatusActive  = "ACTIVE"
	analysisModelVersionStatusTesting = "TESTING"
)

// ResolveAnalysisModel selects the best organization-scoped
// model registration for a job. ACTIVE/default versions are
// preferred, while DEVELOPMENT/TESTING registrations remain
// available as auditable placeholders for safe fallback jobs.
func (r *Repository) ResolveAnalysisModel(
	ctx context.Context,
	organizationID uuid.UUID,
	jobType string,
	mediaType string,
) (*AnalysisModelReference, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	jobType = NormalizeConstant(jobType)
	mediaType = NormalizeConstant(mediaType)

	if ctx == nil ||
		organizationID == uuid.Nil ||
		!IsSupportedJobType(jobType) ||
		!IsSupportedMediaType(mediaType) {
		return nil, ErrInvalidRepositoryInput
	}

	query := `
		SELECT
			m.id,
			v.id,
			m.model_code,
			m.model_name,
			m.model_type,
			m.status,
			m.framework,
			m.input_type,
			m.output_type,
			m.supports_cpu,
			m.supports_gpu,
			m.maximum_file_size_bytes,
			v.version_number,
			v.model_file_path,
			v.model_file_hash,
			v.model_format,
			v.status,
			v.is_default,
			v.confidence_threshold,
			COALESCE(v.configuration, '{}'::jsonb)
		FROM ai_models AS m
		INNER JOIN ai_model_versions AS v
			ON v.ai_model_id = m.id
		WHERE m.organization_id = $1
			AND (
				(
					$2 = 'AI_GENERATED_IMAGE_DETECTION'
					AND (
						COALESCE(
							v.configuration->>'detector_scope',
							''
						) = 'AI_GENERATED_IMAGE_DETECTION'
						OR COALESCE(
							v.configuration->>'positive_class_semantics',
							''
						) IN (
							'AI_GENERATED',
							'AI_GENERATED_OR_FACE_MANIPULATED'
						)
					)
				)
				OR (
					$2 = 'DEEPFAKE_IMAGE_DETECTION'
					AND m.model_type = 'DEEPFAKE_IMAGE_DETECTION'
					AND COALESCE(
						v.configuration->>'detector_scope',
						'DEEPFAKE_IMAGE_DETECTION'
					) = 'DEEPFAKE_IMAGE_DETECTION'
				)
				OR (
					$2 NOT IN (
						'AI_GENERATED_IMAGE_DETECTION',
						'DEEPFAKE_IMAGE_DETECTION'
					)
					AND m.model_type = $2
				)
			)
			AND m.deleted_at IS NULL
			AND m.status IN ($4, $5)
			AND v.status IN ($6, $7)
			AND (
				m.input_type = $3
				OR $2 = $8
			)
		ORDER BY
			CASE
				WHEN m.status = $4
					AND v.status = $6
					AND v.is_default = TRUE
					THEN 0
				WHEN m.status = $4
					AND v.status = $6
					THEN 1
				WHEN v.status = $7
					THEN 2
				ELSE 3
			END,
			v.created_at DESC,
			v.id DESC
		LIMIT 1
	`

	model, err := scanAnalysisModelReference(
		r.databasePool.QueryRow(
			ctx,
			query,
			organizationID,
			jobType,
			mediaType,
			analysisModelStatusActive,
			analysisModelStatusDevelopment,
			analysisModelVersionStatusActive,
			analysisModelVersionStatusTesting,
			JobTypeOCRExtraction,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisModelNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"resolve AI analysis model: %w",
			err,
		)
	}

	return model, nil
}

// GetAnalysisModelReference reloads the exact model and
// version assigned to a queued organization job.
func (r *Repository) GetAnalysisModelReference(
	ctx context.Context,
	organizationID uuid.UUID,
	modelID uuid.UUID,
	modelVersionID uuid.UUID,
) (*AnalysisModelReference, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	if ctx == nil ||
		organizationID == uuid.Nil ||
		modelID == uuid.Nil ||
		modelVersionID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	query := `
		SELECT
			m.id,
			v.id,
			m.model_code,
			m.model_name,
			m.model_type,
			m.status,
			m.framework,
			m.input_type,
			m.output_type,
			m.supports_cpu,
			m.supports_gpu,
			m.maximum_file_size_bytes,
			v.version_number,
			v.model_file_path,
			v.model_file_hash,
			v.model_format,
			v.status,
			v.is_default,
			v.confidence_threshold,
			COALESCE(v.configuration, '{}'::jsonb)
		FROM ai_models AS m
		INNER JOIN ai_model_versions AS v
			ON v.ai_model_id = m.id
		WHERE m.organization_id = $1
			AND m.id = $2
			AND v.id = $3
			AND m.deleted_at IS NULL
	`

	model, err := scanAnalysisModelReference(
		r.databasePool.QueryRow(
			ctx,
			query,
			organizationID,
			modelID,
			modelVersionID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisModelNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"get AI analysis model reference: %w",
			err,
		)
	}

	return model, nil
}

// IsInferenceReady reports whether a verified trained-model
// file may be supplied to the Python inference service.
// CUSTOM and TESTING registrations deliberately use the
// classical/heuristic runtime instead.
func (m AnalysisModelReference) IsInferenceReady() bool {
	if NormalizeConstant(m.ModelStatus) !=
		analysisModelStatusActive ||
		NormalizeConstant(m.VersionStatus) !=
			analysisModelVersionStatusActive ||
		!m.IsDefault ||
		strings.TrimSpace(m.ModelFilePath) == "" ||
		strings.TrimSpace(m.ModelFileHash) == "" {
		return false
	}

	switch NormalizeConstant(m.ModelFormat) {
	case "PTH", "PT", "ONNX":
		return true

	default:
		return false
	}
}

func scanAnalysisModelReference(
	scanner databaseRowScanner,
) (*AnalysisModelReference, error) {
	if scanner == nil {
		return nil, ErrRepositoryUnavailable
	}

	model := &AnalysisModelReference{}
	var configurationJSON []byte

	err := scanner.Scan(
		&model.ModelID,
		&model.ModelVersionID,
		&model.ModelCode,
		&model.ModelName,
		&model.ModelType,
		&model.ModelStatus,
		&model.Framework,
		&model.InputType,
		&model.OutputType,
		&model.SupportsCPU,
		&model.SupportsGPU,
		&model.MaximumFileSizeBytes,
		&model.VersionNumber,
		&model.ModelFilePath,
		&model.ModelFileHash,
		&model.ModelFormat,
		&model.VersionStatus,
		&model.IsDefault,
		&model.ConfidenceThreshold,
		&configurationJSON,
	)
	if err != nil {
		return nil, err
	}

	model.Configuration = map[string]any{}
	if len(configurationJSON) > 0 {
		if err = json.Unmarshal(
			configurationJSON,
			&model.Configuration,
		); err != nil {
			return nil, fmt.Errorf(
				"decode AI model configuration: %w",
				err,
			)
		}
	}

	return model, nil
}
