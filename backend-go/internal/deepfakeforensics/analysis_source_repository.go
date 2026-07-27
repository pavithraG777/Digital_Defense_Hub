package deepfakeforensics

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LoadAnalysisSource resolves the claimed job, its
// organization media asset and exact assigned model
// registration before worker execution.
func (r *Repository) LoadAnalysisSource(
	ctx context.Context,
	jobID uuid.UUID,
) (*AnalysisSource, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	if ctx == nil || jobID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	job, err := r.getProcessingAnalysisJob(
		ctx,
		jobID,
	)
	if err != nil {
		return nil, err
	}

	if job.MediaAssetID == nil ||
		*job.MediaAssetID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: analysis job has no media asset",
			ErrInvalidRepositoryInput,
		)
	}

	asset, err := r.GetMediaAsset(
		ctx,
		job.OrganizationID,
		*job.MediaAssetID,
	)
	if err != nil {
		return nil, err
	}

	model, err := r.GetAnalysisModelReference(
		ctx,
		job.OrganizationID,
		job.AIModelID,
		job.AIModelVersionID,
	)
	if err != nil {
		return nil, err
	}

	if asset.OrganizationID != job.OrganizationID {
		return nil, fmt.Errorf(
			"%w: media asset organization mismatch",
			ErrInvalidRepositoryInput,
		)
	}

	if NormalizeConstant(model.ModelType) !=
		NormalizeConstant(job.JobType) {
		return nil, fmt.Errorf(
			"%w: assigned model type does not match job type",
			ErrInvalidRepositoryInput,
		)
	}

	return &AnalysisSource{
		Asset: *asset,
		Model: *model,
		Job:   *job,
	}, nil
}

func (r *Repository) getProcessingAnalysisJob(
	ctx context.Context,
	jobID uuid.UUID,
) (*AIAnalysisJob, error) {
	query := `
		SELECT
			id,
			organization_id,
			incident_id,
			media_asset_id,
			evidence_id,
			evidence_file_id,
			ai_model_id,
			ai_model_version_id,
			job_number,
			job_type,
			priority,
			status,
			requested_by,
			COALESCE(request_parameters, '{}'::jsonb),
			COALESCE(response_data, '{}'::jsonb),
			progress_percentage,
			retry_count,
			maximum_retries,
			error_code,
			error_message,
			processing_node,
			execution_device,
			processing_duration_ms,
			queued_at,
			started_at,
			completed_at,
			cancelled_at,
			created_at,
			updated_at
		FROM ai_analysis_jobs
		WHERE id = $1
			AND status = $2
	`

	job, err := scanAIAnalysisJob(
		r.databasePool.QueryRow(
			ctx,
			query,
			jobID,
			JobStatusProcessing,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisJobConflict
	}
	if err != nil {
		return nil, fmt.Errorf(
			"load processing AI analysis job: %w",
			err,
		)
	}

	return job, nil
}
