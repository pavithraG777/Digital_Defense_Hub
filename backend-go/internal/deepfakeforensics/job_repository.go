package deepfakeforensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	defaultAnalysisJobMaximumRetries = 3
	maximumAnalysisJobRetries        = 10
)

// CreateAnalysisJobInput contains one normalized job and
// the organization model registration assigned to it.
type CreateAnalysisJobInput struct {
	OrganizationID uuid.UUID
	IncidentID     *uuid.UUID

	MediaAssetID   *uuid.UUID
	EvidenceID     *uuid.UUID
	EvidenceFileID *uuid.UUID

	Model AnalysisModelReference

	JobType  string
	Priority string

	RequestedBy uuid.UUID

	RequestParameters map[string]any
	ExecutionDevice   string
	MaximumRetries    int
}

// CreateAnalysisJobs atomically persists one or more
// organization-scoped analysis jobs.
func (r *Repository) CreateAnalysisJobs(
	ctx context.Context,
	inputs []CreateAnalysisJobInput,
) ([]AIAnalysisJob, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	if ctx == nil || len(inputs) == 0 {
		return nil, ErrInvalidRepositoryInput
	}

	tx, err := r.databasePool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"begin AI analysis job transaction: %w",
			err,
		)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	jobs := make(
		[]AIAnalysisJob,
		0,
		len(inputs),
	)

	for _, input := range inputs {
		job, createErr := createAnalysisJob(
			ctx,
			tx,
			input,
		)
		if createErr != nil {
			return nil, createErr
		}

		jobs = append(jobs, *job)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit AI analysis jobs: %w",
			err,
		)
	}

	return jobs, nil
}

// GetAnalysisJob returns one organization-scoped job.
func (r *Repository) GetAnalysisJob(
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
		WHERE organization_id = $1
			AND id = $2
	`

	job, err := scanAIAnalysisJob(
		r.databasePool.QueryRow(
			ctx,
			query,
			organizationID,
			jobID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAnalysisJobNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"get AI analysis job: %w",
			err,
		)
	}

	return job, nil
}

// ListAnalysisJobs returns filtered organization jobs and
// their total count.
func (r *Repository) ListAnalysisJobs(
	ctx context.Context,
	organizationID uuid.UUID,
	filter AnalysisJobListFilter,
) ([]AIAnalysisJob, int64, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, 0, err
	}

	if ctx == nil || organizationID == uuid.Nil {
		return nil, 0, ErrInvalidRepositoryInput
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	conditions := []string{
		"organization_id = $1",
	}
	arguments := []any{
		organizationID,
	}

	addFilter := func(
		condition string,
		value any,
	) {
		arguments = append(arguments, value)
		conditions = append(
			conditions,
			fmt.Sprintf(
				condition,
				len(arguments),
			),
		)
	}

	if filter.MediaAssetID != nil {
		addFilter(
			"media_asset_id = $%d",
			*filter.MediaAssetID,
		)
	}

	if jobType := NormalizeConstant(
		filter.JobType,
	); jobType != "" {
		addFilter(
			"job_type = $%d",
			jobType,
		)
	}

	if status := NormalizeConstant(
		filter.Status,
	); status != "" {
		addFilter(
			"status = $%d",
			status,
		)
	}

	if priority := NormalizeConstant(
		filter.Priority,
	); priority != "" {
		addFilter(
			"priority = $%d",
			priority,
		)
	}

	if filter.CreatedFrom != nil {
		addFilter(
			"created_at >= $%d",
			filter.CreatedFrom.UTC(),
		)
	}

	if filter.CreatedTo != nil {
		addFilter(
			"created_at <= $%d",
			filter.CreatedTo.UTC(),
		)
	}

	arguments = append(arguments, limit)
	limitPlaceholder := len(arguments)
	arguments = append(arguments, offset)
	offsetPlaceholder := len(arguments)

	query := fmt.Sprintf(
		`
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
				updated_at,
				COUNT(*) OVER()
			FROM ai_analysis_jobs
			WHERE %s
			ORDER BY
				CASE priority
					WHEN 'URGENT' THEN 0
					WHEN 'HIGH' THEN 1
					WHEN 'NORMAL' THEN 2
					ELSE 3
				END,
				created_at DESC,
				id DESC
			LIMIT $%d
			OFFSET $%d
		`,
		strings.Join(conditions, " AND "),
		limitPlaceholder,
		offsetPlaceholder,
	)

	rows, err := r.databasePool.Query(
		ctx,
		query,
		arguments...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list AI analysis jobs: %w",
			err,
		)
	}
	defer rows.Close()

	items := make(
		[]AIAnalysisJob,
		0,
		limit,
	)
	var total int64

	for rows.Next() {
		var rowTotal int64

		job, scanErr := scanAIAnalysisJob(
			rows,
			&rowTotal,
		)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan AI analysis job: %w",
				scanErr,
			)
		}

		total = rowTotal
		items = append(items, *job)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate AI analysis jobs: %w",
			err,
		)
	}

	return items, total, nil
}

func createAnalysisJob(
	ctx context.Context,
	tx pgx.Tx,
	input CreateAnalysisJobInput,
) (*AIAnalysisJob, error) {
	if err := validateCreateAnalysisJobInput(
		input,
	); err != nil {
		return nil, err
	}

	jobID := uuid.New()
	now := time.Now().UTC()
	priority := NormalizeConstant(input.Priority)
	if priority == "" {
		priority = JobPriorityNormal
	}

	executionDevice := NormalizeConstant(
		input.ExecutionDevice,
	)
	if executionDevice == "" {
		executionDevice = "CPU"
	}

	maximumRetries := input.MaximumRetries
	if maximumRetries <= 0 {
		maximumRetries =
			defaultAnalysisJobMaximumRetries
	}

	requestParameters := input.RequestParameters
	if requestParameters == nil {
		requestParameters = map[string]any{}
	}

	requestParametersJSON, err := json.Marshal(
		requestParameters,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: encode AI analysis request parameters: %v",
			ErrInvalidRepositoryInput,
			err,
		)
	}

	query := `
		INSERT INTO ai_analysis_jobs (
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
			request_parameters,
			progress_percentage,
			retry_count,
			maximum_retries,
			execution_device,
			queued_at,
			created_at,
			updated_at
		)
		VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, 0,
			0, $15, $16, $17, $17, $17
		)
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
		tx.QueryRow(
			ctx,
			query,
			jobID,
			input.OrganizationID,
			input.IncidentID,
			input.MediaAssetID,
			input.EvidenceID,
			input.EvidenceFileID,
			input.Model.ModelID,
			input.Model.ModelVersionID,
			buildAnalysisJobNumber(jobID, now),
			NormalizeConstant(input.JobType),
			priority,
			JobStatusQueued,
			input.RequestedBy,
			requestParametersJSON,
			maximumRetries,
			executionDevice,
			now,
		),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAnalysisJobConflict
		}

		return nil, fmt.Errorf(
			"create AI analysis job: %w",
			err,
		)
	}

	return job, nil
}

func validateCreateAnalysisJobInput(
	input CreateAnalysisJobInput,
) error {
	hasSource := input.MediaAssetID != nil ||
		input.EvidenceID != nil

	maximumRetries := input.MaximumRetries
	if maximumRetries < 0 ||
		maximumRetries > maximumAnalysisJobRetries {
		return ErrInvalidRepositoryInput
	}

	priority := NormalizeConstant(input.Priority)
	if priority != "" &&
		!IsSupportedJobPriority(priority) {
		return ErrInvalidRepositoryInput
	}

	executionDevice := NormalizeConstant(
		input.ExecutionDevice,
	)
	if executionDevice != "" &&
		executionDevice != "AUTO" &&
		executionDevice != "CPU" &&
		executionDevice != "CUDA" {
		return ErrInvalidRepositoryInput
	}

	if input.OrganizationID == uuid.Nil ||
		input.RequestedBy == uuid.Nil ||
		input.Model.ModelID == uuid.Nil ||
		input.Model.ModelVersionID == uuid.Nil ||
		!hasSource ||
		!IsSupportedJobType(input.JobType) {
		return ErrInvalidRepositoryInput
	}

	return nil
}

func buildAnalysisJobNumber(
	jobID uuid.UUID,
	now time.Time,
) string {
	return fmt.Sprintf(
		"DDH-AI-%s-%s",
		now.UTC().Format("20060102"),
		strings.ToUpper(
			strings.ReplaceAll(
				jobID.String()[:8],
				"-",
				"",
			),
		),
	)
}

func scanAIAnalysisJob(
	scanner databaseRowScanner,
	additionalDestinations ...any,
) (*AIAnalysisJob, error) {
	if scanner == nil {
		return nil, ErrRepositoryUnavailable
	}

	job := &AIAnalysisJob{}
	var requestParametersJSON []byte
	var responseDataJSON []byte

	destinations := []any{
		&job.ID,
		&job.OrganizationID,
		&job.IncidentID,
		&job.MediaAssetID,
		&job.EvidenceID,
		&job.EvidenceFileID,
		&job.AIModelID,
		&job.AIModelVersionID,
		&job.JobNumber,
		&job.JobType,
		&job.Priority,
		&job.Status,
		&job.RequestedBy,
		&requestParametersJSON,
		&responseDataJSON,
		&job.ProgressPercentage,
		&job.RetryCount,
		&job.MaximumRetries,
		&job.ErrorCode,
		&job.ErrorMessage,
		&job.ProcessingNode,
		&job.ExecutionDevice,
		&job.ProcessingDurationMS,
		&job.QueuedAt,
		&job.StartedAt,
		&job.CompletedAt,
		&job.CancelledAt,
		&job.CreatedAt,
		&job.UpdatedAt,
	}
	destinations = append(
		destinations,
		additionalDestinations...,
	)

	if err := scanner.Scan(
		destinations...,
	); err != nil {
		return nil, err
	}

	job.RequestParameters = map[string]any{}
	if len(requestParametersJSON) > 0 {
		if err := json.Unmarshal(
			requestParametersJSON,
			&job.RequestParameters,
		); err != nil {
			return nil, fmt.Errorf(
				"decode AI analysis request parameters: %w",
				err,
			)
		}
	}

	job.ResponseData = map[string]any{}
	if len(responseDataJSON) > 0 {
		if err := json.Unmarshal(
			responseDataJSON,
			&job.ResponseData,
		); err != nil {
			return nil, fmt.Errorf(
				"decode AI analysis response data: %w",
				err,
			)
		}
	}

	return job, nil
}
