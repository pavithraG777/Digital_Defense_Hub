package deepfakeforensics

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *AnalysisService) RetryAnalysisJob(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
	actorUserID uuid.UUID,
) (*AIAnalysisJob, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		analysisJobID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidAnalysisRequest
	}

	return s.repository.RetryAnalysisJob(
		ctx,
		organizationID,
		analysisJobID,
		actorUserID,
	)
}

// RetryAnalysisJob manually requeues only terminal failed
// or cancelled work. The active-job unique index prevents
// a duplicate job type from being scheduled concurrently.
func (r *Repository) RetryAnalysisJob(
	ctx context.Context,
	organizationID uuid.UUID,
	jobID uuid.UUID,
	actorUserID uuid.UUID,
) (*AIAnalysisJob, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}
	if ctx == nil ||
		organizationID == uuid.Nil ||
		jobID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	query := `
		UPDATE ai_analysis_jobs AS job
		SET
			status = $4::varchar,
			requested_by = $3::uuid,
			request_parameters = COALESCE(
				request_parameters,
				'{}'::jsonb
			) || jsonb_build_object(
				'manual_retry',
				true,
				'manual_retry_requested_by',
				($3::uuid)::text,
				'manual_retry_requested_at',
				CURRENT_TIMESTAMP
			),
			response_data = '{}'::jsonb,
			progress_percentage = 0,
			retry_count = 0,
			error_code = NULL,
			error_message = NULL,
			processing_node = NULL,
			processing_duration_ms = NULL,
			queued_at = CURRENT_TIMESTAMP,
			started_at = NULL,
			completed_at = NULL,
			cancelled_at = NULL,
			updated_at = CURRENT_TIMESTAMP
		FROM media_analysis_assets AS asset
		WHERE job.organization_id = $1::uuid
			AND job.id = $2::uuid
			AND job.status IN (
				$5::varchar,
				$6::varchar
			)
			AND asset.organization_id =
				job.organization_id
			AND asset.id = job.media_asset_id
			AND asset.status = $7::varchar
			AND asset.deleted_at IS NULL
		RETURNING
			job.id,
			job.organization_id,
			job.incident_id,
			job.media_asset_id,
			job.evidence_id,
			job.evidence_file_id,
			job.ai_model_id,
			job.ai_model_version_id,
			job.job_number,
			job.job_type,
			job.priority,
			job.status,
			job.requested_by,
			COALESCE(
				job.request_parameters,
				'{}'::jsonb
			),
			COALESCE(
				job.response_data,
				'{}'::jsonb
			),
			job.progress_percentage,
			job.retry_count,
			job.maximum_retries,
			job.error_code,
			job.error_message,
			job.processing_node,
			job.execution_device,
			job.processing_duration_ms,
			job.queued_at,
			job.started_at,
			job.completed_at,
			job.cancelled_at,
			job.created_at,
			job.updated_at
	`

	job, err := scanAIAnalysisJob(
		r.databasePool.QueryRow(
			ctx,
			query,
			organizationID,
			jobID,
			actorUserID,
			JobStatusQueued,
			JobStatusFailed,
			JobStatusCancelled,
			mediaAssetStatusAvailable,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		_, getErr := r.GetAnalysisJob(
			ctx,
			organizationID,
			jobID,
		)
		if errors.Is(
			getErr,
			ErrAnalysisJobNotFound,
		) {
			return nil, getErr
		}
		return nil, ErrAnalysisJobConflict
	}
	if isUniqueViolation(err) {
		return nil, ErrAnalysisJobConflict
	}
	if err != nil {
		return nil, fmt.Errorf(
			"retry AI analysis job: %w",
			err,
		)
	}

	return job, nil
}

// IsAnalysisJobCancelled lets a worker cooperatively stop
// a running Python request after an API cancellation.
func (r *Repository) IsAnalysisJobCancelled(
	ctx context.Context,
	jobID uuid.UUID,
) (bool, error) {
	if err := r.validateAvailable(); err != nil {
		return false, err
	}
	if ctx == nil ||
		jobID == uuid.Nil {
		return false, ErrInvalidRepositoryInput
	}

	var cancelled bool
	err := r.databasePool.QueryRow(
		ctx,
		`
			SELECT status = $2
			FROM ai_analysis_jobs
			WHERE id = $1
		`,
		jobID,
		JobStatusCancelled,
	).Scan(&cancelled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrAnalysisJobNotFound
	}
	if err != nil {
		return false, fmt.Errorf(
			"inspect AI analysis cancellation: %w",
			err,
		)
	}

	return cancelled, nil
}
