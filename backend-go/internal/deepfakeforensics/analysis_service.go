package deepfakeforensics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidAnalysisRequest = errors.New(
		"invalid media analysis request",
	)
	ErrUnsupportedAnalysisMode = errors.New(
		"unsupported analysis mode for media type",
	)
)

// AnalysisService validates API requests, resolves the
// organization's registered models and queues durable jobs.
type AnalysisService struct {
	repository *Repository
}

func NewAnalysisService(
	repository *Repository,
) (*AnalysisService, error) {
	if repository == nil ||
		!repository.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}

	return &AnalysisService{
		repository: repository,
	}, nil
}

// StartMediaAnalysis queues all requested analysis modes
// for one organization-owned media asset. Unless forced,
// reusable queued or completed jobs are returned instead of
// creating duplicate work.
func (s *AnalysisService) StartMediaAnalysis(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
	requestedBy uuid.UUID,
	request StartMediaAnalysisRequest,
) (*StartMediaAnalysisResponse, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		mediaAssetID == uuid.Nil ||
		requestedBy == uuid.Nil {
		return nil, ErrInvalidAnalysisRequest
	}

	asset, err := s.repository.GetMediaAsset(
		ctx,
		organizationID,
		mediaAssetID,
	)
	if err != nil {
		return nil, err
	}

	if NormalizeConstant(asset.Status) !=
		mediaAssetStatusAvailable {
		return nil, fmt.Errorf(
			"%w: media asset is not available",
			ErrInvalidAnalysisRequest,
		)
	}

	priority := NormalizeConstant(
		request.Priority,
	)
	if priority == "" {
		priority = JobPriorityNormal
	}
	if !IsSupportedJobPriority(priority) {
		return nil, fmt.Errorf(
			"%w: unsupported job priority",
			ErrInvalidAnalysisRequest,
		)
	}

	executionDevice := NormalizeConstant(
		request.ExecutionDevice,
	)
	if executionDevice == "" {
		executionDevice = "CPU"
	}
	if executionDevice != "CPU" &&
		executionDevice != "CUDA" &&
		executionDevice != "AUTO" {
		return nil, fmt.Errorf(
			"%w: unsupported execution device",
			ErrInvalidAnalysisRequest,
		)
	}

	jobTypes, err := jobTypesForAnalysisModes(
		asset.MediaType,
		request.AnalysisModes,
	)
	if err != nil {
		return nil, err
	}

	reusableJobs := map[string]AIAnalysisJob{}
	reusableJobs, err =
		s.repository.findReusableAnalysisJobs(
			ctx,
			organizationID,
			mediaAssetID,
			jobTypes,
		)
	if err != nil {
		return nil, err
	}
	if request.ForceReanalysis {
		for jobType, reusableJob := range reusableJobs {
			switch NormalizeConstant(
				reusableJob.Status,
			) {
			case JobStatusQueued,
				JobStatusProcessing,
				JobStatusRetrying:
				// Active work is always reused. Force only
				// bypasses completed reusable results.

			default:
				delete(
					reusableJobs,
					jobType,
				)
			}
		}
	}

	createInputs := make(
		[]CreateAnalysisJobInput,
		0,
		len(jobTypes),
	)

	for _, jobType := range jobTypes {
		if _, exists := reusableJobs[jobType]; exists {
			continue
		}

		model, resolveErr :=
			s.repository.ResolveAnalysisModel(
				ctx,
				organizationID,
				jobType,
				asset.MediaType,
			)
		if resolveErr != nil {
			return nil, resolveErr
		}

		if supportErr :=
			validateExecutionDeviceSupport(
				*model,
				executionDevice,
			); supportErr != nil {
			return nil, supportErr
		}

		if model.MaximumFileSizeBytes != nil &&
			*model.MaximumFileSizeBytes > 0 &&
			asset.FileSizeBytes >
				*model.MaximumFileSizeBytes {
			return nil, fmt.Errorf(
				"%w: file exceeds %s model size limit",
				ErrInvalidAnalysisRequest,
				jobType,
			)
		}

		createInputs = append(
			createInputs,
			CreateAnalysisJobInput{
				OrganizationID: organizationID,
				IncidentID:     asset.IncidentID,

				MediaAssetID:   mediaAssetUUIDPointer(asset.ID),
				EvidenceID:     asset.EvidenceID,
				EvidenceFileID: asset.EvidenceFileID,

				Model: *model,

				JobType:  jobType,
				Priority: priority,

				RequestedBy: requestedBy,

				RequestParameters: map[string]any{
					"analysis_mode": analysisModeForJobType(
						jobType,
					),
					"create_visualization": jobType !=
						JobTypeOCRExtraction,
					"force_reanalysis": request.ForceReanalysis,
				},
				ExecutionDevice: executionDevice,
			},
		)
	}

	createdJobs := []AIAnalysisJob{}
	if len(createInputs) > 0 {
		createdJobs, err =
			s.repository.CreateAnalysisJobs(
				ctx,
				createInputs,
			)
		if err != nil {
			return nil, err
		}
	}

	jobsByType := make(
		map[string]AIAnalysisJob,
		len(reusableJobs)+len(createdJobs),
	)
	for jobType, job := range reusableJobs {
		jobsByType[jobType] = job
	}
	for _, job := range createdJobs {
		jobType := NormalizeConstant(
			job.JobType,
		)
		jobsByType[jobType] = job
	}

	jobSummaries := make(
		[]AnalysisJobSummary,
		0,
		len(jobTypes),
	)
	for _, jobType := range jobTypes {
		job, exists := jobsByType[jobType]
		if !exists {
			return nil, fmt.Errorf(
				"%w: queued job result is incomplete",
				ErrInvalidAnalysisRequest,
			)
		}

		jobSummaries = append(
			jobSummaries,
			AnalysisJobSummary{
				ID:        job.ID,
				JobNumber: job.JobNumber,
				JobType:   job.JobType,
				Priority:  job.Priority,
				Status:    job.Status,
			},
		)
	}

	return &StartMediaAnalysisResponse{
		Asset: *asset,
		Jobs:  jobSummaries,

		SubmittedAt: time.Now().UTC(),
	}, nil
}

func (s *AnalysisService) isAvailable() bool {
	return s != nil &&
		s.repository != nil &&
		s.repository.IsAvailable()
}

func jobTypesForAnalysisModes(
	mediaType string,
	analysisModes []string,
) ([]string, error) {
	mediaType = NormalizeConstant(mediaType)
	if !IsSupportedMediaType(mediaType) ||
		len(analysisModes) == 0 {
		return nil, ErrInvalidAnalysisRequest
	}

	jobTypes := make(
		[]string,
		0,
		len(analysisModes)*2,
	)
	seenJobTypes := map[string]struct{}{}

	addJobType := func(jobType string) {
		if _, exists := seenJobTypes[jobType]; exists {
			return
		}

		seenJobTypes[jobType] = struct{}{}
		jobTypes = append(jobTypes, jobType)
	}

	for _, requestedMode := range analysisModes {
		mode := NormalizeConstant(
			requestedMode,
		)
		if !IsSupportedAnalysisMode(mode) {
			return nil, fmt.Errorf(
				"%w: %s",
				ErrUnsupportedAnalysisMode,
				mode,
			)
		}

		switch mode {
		case AnalysisModeDeepfake:
			jobType, ok :=
				deepfakeJobTypeForMedia(
					mediaType,
				)
			if !ok {
				return nil, fmt.Errorf(
					"%w: deepfake analysis does not support %s",
					ErrUnsupportedAnalysisMode,
					mediaType,
				)
			}
			addJobType(jobType)

		case AnalysisModeForensics:
			jobType, ok :=
				forensicsJobTypeForMedia(
					mediaType,
				)
			if !ok {
				return nil, fmt.Errorf(
					"%w: forensic analysis does not support %s",
					ErrUnsupportedAnalysisMode,
					mediaType,
				)
			}
			addJobType(jobType)

		case AnalysisModeCombined:
			deepfakeJobType, deepfakeOK :=
				deepfakeJobTypeForMedia(
					mediaType,
				)
			forensicsJobType, forensicsOK :=
				forensicsJobTypeForMedia(
					mediaType,
				)
			if !deepfakeOK || !forensicsOK {
				return nil, fmt.Errorf(
					"%w: combined analysis does not support %s",
					ErrUnsupportedAnalysisMode,
					mediaType,
				)
			}

			addJobType(deepfakeJobType)
			addJobType(forensicsJobType)

		case AnalysisModeOCR:
			if mediaType != MediaTypeImage &&
				mediaType != MediaTypeVideo &&
				mediaType != MediaTypeDocument {
				return nil, fmt.Errorf(
					"%w: OCR does not support %s",
					ErrUnsupportedAnalysisMode,
					mediaType,
				)
			}

			addJobType(JobTypeOCRExtraction)
		}
	}

	if len(jobTypes) == 0 {
		return nil, ErrInvalidAnalysisRequest
	}

	return jobTypes, nil
}

func deepfakeJobTypeForMedia(
	mediaType string,
) (string, bool) {
	switch NormalizeConstant(mediaType) {
	case MediaTypeImage:
		return JobTypeDeepfakeImage, true

	case MediaTypeVideo:
		return JobTypeDeepfakeVideo, true

	case MediaTypeAudio:
		return JobTypeDeepfakeAudio, true

	default:
		return "", false
	}
}

func forensicsJobTypeForMedia(
	mediaType string,
) (string, bool) {
	switch NormalizeConstant(mediaType) {
	case MediaTypeImage:
		return JobTypeImageForensics, true

	case MediaTypeVideo:
		return JobTypeVideoForensics, true

	case MediaTypeAudio:
		return JobTypeAudioForensics, true

	default:
		return "", false
	}
}

func analysisModeForJobType(
	jobType string,
) string {
	switch {
	case IsDeepfakeJobType(jobType):
		return AnalysisModeDeepfake

	case IsForensicsJobType(jobType):
		return AnalysisModeForensics

	case NormalizeConstant(jobType) ==
		JobTypeOCRExtraction:
		return AnalysisModeOCR

	default:
		return ""
	}
}

func mediaAssetUUIDPointer(
	value uuid.UUID,
) *uuid.UUID {
	if value == uuid.Nil {
		return nil
	}

	copiedValue := value
	return &copiedValue
}

func (r *Repository) findReusableAnalysisJobs(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
	jobTypes []string,
) (map[string]AIAnalysisJob, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}
	if ctx == nil ||
		organizationID == uuid.Nil ||
		mediaAssetID == uuid.Nil ||
		len(jobTypes) == 0 {
		return nil, ErrInvalidRepositoryInput
	}

	normalizedJobTypes := make(
		[]string,
		0,
		len(jobTypes),
	)
	for _, jobType := range jobTypes {
		jobType = NormalizeConstant(jobType)
		if !IsSupportedJobType(jobType) {
			return nil, ErrInvalidRepositoryInput
		}

		normalizedJobTypes = append(
			normalizedJobTypes,
			jobType,
		)
	}

	rows, err := r.databasePool.Query(
		ctx,
		`
			SELECT DISTINCT ON (job_type)
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
			FROM ai_analysis_jobs
			WHERE organization_id = $1
				AND media_asset_id = $2
				AND job_type = ANY($3::varchar[])
				AND status IN (
					$4,
					$5,
					$6,
					$7,
					$8
				)
			ORDER BY
				job_type,
				CASE
					WHEN status IN ($4, $5, $6)
						THEN 0
					ELSE 1
				END,
				created_at DESC,
				id DESC
		`,
		organizationID,
		mediaAssetID,
		normalizedJobTypes,
		JobStatusQueued,
		JobStatusProcessing,
		JobStatusRetrying,
		JobStatusCompleted,
		JobStatusReviewRequired,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"find reusable media analysis jobs: %w",
			err,
		)
	}
	defer rows.Close()

	jobs := make(
		map[string]AIAnalysisJob,
		len(normalizedJobTypes),
	)
	for rows.Next() {
		job, scanErr := scanAIAnalysisJob(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan reusable media analysis job: %w",
				scanErr,
			)
		}

		jobType := NormalizeConstant(
			job.JobType,
		)
		jobs[jobType] = *job
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate reusable media analysis jobs: %w",
			err,
		)
	}

	return jobs, nil
}
