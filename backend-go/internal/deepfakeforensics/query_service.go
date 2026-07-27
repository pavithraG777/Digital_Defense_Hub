package deepfakeforensics

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

const (
	defaultMediaQueryPageSize = 20
	maximumMediaQueryPageSize = 100
)

// QueryService exposes organization-scoped read operations
// without leaking repository pagination details.
type QueryService struct {
	repository *Repository
}

func NewQueryService(
	repository *Repository,
) (*QueryService, error) {
	if repository == nil ||
		!repository.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}

	return &QueryService{
		repository: repository,
	}, nil
}

func (s *QueryService) GetMediaAsset(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
) (*MediaAnalysisAsset, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		mediaAssetID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	return s.repository.GetMediaAsset(
		ctx,
		organizationID,
		mediaAssetID,
	)
}

func (s *QueryService) ListMediaAssets(
	ctx context.Context,
	organizationID uuid.UUID,
	filter MediaAssetListFilter,
) (*MediaAssetListResponse, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	if filter.MediaType != "" {
		filter.MediaType = NormalizeConstant(
			filter.MediaType,
		)
		if !IsSupportedMediaType(
			filter.MediaType,
		) {
			return nil, fmt.Errorf(
				"%w: unsupported media type",
				ErrInvalidRepositoryInput,
			)
		}
	}

	filter.Status = NormalizeConstant(
		filter.Status,
	)
	filter.SourceType = NormalizeConstant(
		filter.SourceType,
	)
	filter.Limit, filter.Offset =
		normalizeMediaPagination(
			filter.Limit,
			filter.Offset,
		)

	items, total, err :=
		s.repository.ListMediaAssets(
			ctx,
			organizationID,
			filter,
		)
	if err != nil {
		return nil, err
	}

	page, totalPages := calculateMediaPages(
		total,
		filter.Limit,
		filter.Offset,
	)

	return &MediaAssetListResponse{
		Items: items,

		Total:      total,
		Page:       page,
		PageSize:   filter.Limit,
		TotalPages: totalPages,
	}, nil
}

func (s *QueryService) GetAnalysisJob(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*AIAnalysisJob, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		analysisJobID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	return s.repository.GetAnalysisJob(
		ctx,
		organizationID,
		analysisJobID,
	)
}

func (s *QueryService) ListAnalysisJobs(
	ctx context.Context,
	organizationID uuid.UUID,
	filter AnalysisJobListFilter,
) (*AnalysisJobListResponse, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	filter.JobType = NormalizeConstant(
		filter.JobType,
	)
	if filter.JobType != "" &&
		!IsSupportedJobType(filter.JobType) {
		return nil, fmt.Errorf(
			"%w: unsupported analysis job type",
			ErrInvalidRepositoryInput,
		)
	}

	filter.Status = NormalizeConstant(
		filter.Status,
	)
	if filter.Status != "" &&
		!isSupportedAnalysisJobStatus(
			filter.Status,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported analysis job status",
			ErrInvalidRepositoryInput,
		)
	}

	filter.Priority = NormalizeConstant(
		filter.Priority,
	)
	if filter.Priority != "" &&
		!IsSupportedJobPriority(
			filter.Priority,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported analysis job priority",
			ErrInvalidRepositoryInput,
		)
	}

	filter.Limit, filter.Offset =
		normalizeMediaPagination(
			filter.Limit,
			filter.Offset,
		)

	items, total, err :=
		s.repository.ListAnalysisJobs(
			ctx,
			organizationID,
			filter,
		)
	if err != nil {
		return nil, err
	}

	page, totalPages := calculateMediaPages(
		total,
		filter.Limit,
		filter.Offset,
	)

	return &AnalysisJobListResponse{
		Items: items,

		Total:      total,
		Page:       page,
		PageSize:   filter.Limit,
		TotalPages: totalPages,
	}, nil
}

func (s *QueryService) GetAnalysisResult(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*AnalysisResultBundle, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		analysisJobID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	return s.repository.GetAnalysisResult(
		ctx,
		organizationID,
		analysisJobID,
	)
}

func (s *QueryService) isAvailable() bool {
	return s != nil &&
		s.repository != nil &&
		s.repository.IsAvailable()
}

func normalizeMediaPagination(
	limit int,
	offset int,
) (int, int) {
	if limit <= 0 {
		limit = defaultMediaQueryPageSize
	}
	if limit > maximumMediaQueryPageSize {
		limit = maximumMediaQueryPageSize
	}
	if offset < 0 {
		offset = 0
	}

	return limit, offset
}

func calculateMediaPages(
	total int64,
	pageSize int,
	offset int,
) (int, int) {
	if pageSize <= 0 {
		pageSize = defaultMediaQueryPageSize
	}

	page := offset/pageSize + 1
	totalPages := 0
	if total > 0 {
		totalPages = int(
			(total + int64(pageSize) - 1) /
				int64(pageSize),
		)
	}

	return page, totalPages
}

func isSupportedAnalysisJobStatus(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case JobStatusPending,
		JobStatusQueued,
		JobStatusProcessing,
		JobStatusCompleted,
		JobStatusFailed,
		JobStatusCancelled,
		JobStatusRetrying,
		JobStatusReviewRequired:
		return true

	default:
		return false
	}
}
