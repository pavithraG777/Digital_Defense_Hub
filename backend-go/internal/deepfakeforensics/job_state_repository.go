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

// ClaimAnalysisJobs atomically assigns queued work to one
// processing node. SKIP LOCKED permits multiple workers
// without duplicate job execution.
func (r *Repository) ClaimAnalysisJobs(
	ctx context.Context,
	limit int,
	processingNode string,
) ([]AIAnalysisJob, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	processingNode = strings.TrimSpace(
		processingNode,
	)
	if ctx == nil || processingNode == "" {
		return nil, ErrInvalidRepositoryInput
	}

	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}

	query := `
		WITH selected_jobs AS (
			SELECT id
			FROM ai_analysis_jobs
			WHERE (
				status = $1
				OR (
					status = $2
					AND updated_at <=
						CURRENT_TIMESTAMP
						- (
							LEAST(
								300,
								(
									5 * POWER(
										2,
										LEAST(
											retry_count,
											6
										)
									)
								)::integer
							) * INTERVAL '1 second'
						)
				)
			)
				AND retry_count < maximum_retries
			ORDER BY
				CASE priority
					WHEN 'URGENT' THEN 0
					WHEN 'HIGH' THEN 1
					WHEN 'NORMAL' THEN 2
					ELSE 3
				END,
				queued_at ASC NULLS FIRST,
				created_at ASC,
				id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		UPDATE ai_analysis_jobs AS job
		SET
			status = $4,
			progress_percentage = 5,
			processing_node = $5,
			started_at = CURRENT_TIMESTAMP,
			error_code = NULL,
			error_message = NULL,
			updated_at = CURRENT_TIMESTAMP
		FROM selected_jobs
		WHERE job.id = selected_jobs.id
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

	rows, err := r.databasePool.Query(
		ctx,
		query,
		JobStatusQueued,
		JobStatusRetrying,
		limit,
		JobStatusProcessing,
		processingNode,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"claim AI analysis jobs: %w",
			err,
		)
	}
	defer rows.Close()

	jobs := make(
		[]AIAnalysisJob,
		0,
		limit,
	)

	for rows.Next() {
		job, scanErr := scanAIAnalysisJob(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan claimed AI analysis job: %w",
				scanErr,
			)
		}

		jobs = append(jobs, *job)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate claimed AI analysis jobs: %w",
			err,
		)
	}

	return jobs, nil
}

// UpdateAnalysisJobProgress records bounded progress for
// a currently processing job.
func (r *Repository) UpdateAnalysisJobProgress(
	ctx context.Context,
	jobID uuid.UUID,
	progress float64,
) error {
	if err := r.validateAvailable(); err != nil {
		return err
	}

	if ctx == nil ||
		jobID == uuid.Nil ||
		progress < 0 ||
		progress > 100 {
		return ErrInvalidRepositoryInput
	}

	commandTag, err := r.databasePool.Exec(
		ctx,
		`
			UPDATE ai_analysis_jobs
			SET
				progress_percentage = $2,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
				AND status = $3
		`,
		jobID,
		progress,
		JobStatusProcessing,
	)
	if err != nil {
		return fmt.Errorf(
			"update AI analysis job progress: %w",
			err,
		)
	}
	if commandTag.RowsAffected() == 0 {
		return ErrAnalysisJobConflict
	}

	return nil
}

// RetryOrFailAnalysisJob records an execution failure.
// Remaining attempts transition to RETRYING with bounded
// exponential backoff; the final attempt becomes FAILED.
func (r *Repository) RetryOrFailAnalysisJob(
	ctx context.Context,
	jobID uuid.UUID,
	errorCode string,
	errorMessage string,
	processingDurationMS int64,
	responseData map[string]any,
) (*AIAnalysisJob, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	errorCode = NormalizeConstant(errorCode)
	errorMessage = strings.TrimSpace(
		errorMessage,
	)
	if ctx == nil ||
		jobID == uuid.Nil ||
		errorCode == "" ||
		errorMessage == "" ||
		processingDurationMS < 0 {
		return nil, ErrInvalidRepositoryInput
	}

	if responseData == nil {
		responseData = map[string]any{}
	}
	responseDataJSON, err := json.Marshal(
		responseData,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: encode failed analysis response: %v",
			ErrInvalidRepositoryInput,
			err,
		)
	}

	query := `
		UPDATE ai_analysis_jobs
		SET
			retry_count = retry_count + 1,
			status = CASE
				WHEN retry_count + 1 >= maximum_retries
					THEN $2
				ELSE $3
			END,
			progress_percentage = CASE
				WHEN retry_count + 1 >= maximum_retries
					THEN 100
				ELSE 0
			END,
			error_code = $4,
			error_message = $5,
			response_data = $6,
			processing_duration_ms = $7,
			completed_at = CASE
				WHEN retry_count + 1 >= maximum_retries
					THEN CURRENT_TIMESTAMP
				ELSE NULL
			END,
			queued_at = CASE
				WHEN retry_count + 1 < maximum_retries
					THEN CURRENT_TIMESTAMP
				ELSE queued_at
			END,
			processing_node = CASE
				WHEN retry_count + 1 < maximum_retries
					THEN NULL
				ELSE processing_node
			END,
			started_at = CASE
				WHEN retry_count + 1 < maximum_retries
					THEN NULL
				ELSE started_at
			END,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
			AND status = $8
		RETURNING
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
			COALESCE(
				request_parameters,
				'{}'::jsonb
			),
			COALESCE(
				response_data,
				'{}'::jsonb
			),
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
	`

	job, err := scanAIAnalysisJob(
		r.databasePool.QueryRow(
			ctx,
			query,
			jobID,
			JobStatusFailed,
			JobStatusRetrying,
			errorCode,
			errorMessage,
			responseDataJSON,
			processingDurationMS,
			JobStatusProcessing,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisJobConflict
	}
	if err != nil {
		return nil, fmt.Errorf(
			"retry or fail AI analysis job: %w",
			err,
		)
	}

	return job, nil
}

// CancelAnalysisJob cancels a job that has not begun
// processing. Running work must be stopped cooperatively by
// the worker before it can be cancelled.
func (r *Repository) CancelAnalysisJob(
	ctx context.Context,
	organizationID uuid.UUID,
	jobID uuid.UUID,
) (*AIAnalysisJob, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	if ctx == nil ||
		organizationID == uuid.Nil ||
		jobID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	query := `
		UPDATE ai_analysis_jobs
		SET
			status = $3,
			progress_percentage = 100,
			cancelled_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE organization_id = $1
			AND id = $2
			AND status IN ($4, $5)
		RETURNING
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
			COALESCE(
				request_parameters,
				'{}'::jsonb
			),
			COALESCE(
				response_data,
				'{}'::jsonb
			),
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
	`

	job, err := scanAIAnalysisJob(
		r.databasePool.QueryRow(
			ctx,
			query,
			organizationID,
			jobID,
			JobStatusCancelled,
			JobStatusQueued,
			JobStatusRetrying,
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
			return nil, ErrAnalysisJobNotFound
		}

		return nil, ErrAnalysisJobConflict
	}
	if err != nil {
		return nil, fmt.Errorf(
			"cancel AI analysis job: %w",
			err,
		)
	}

	return job, nil
}
