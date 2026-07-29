package deepfakeforensics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

// Handler exposes authenticated organization-scoped media
// upload, analysis job and result endpoints.
type Handler struct {
	assetService    *AssetService
	analysisService *AnalysisService
	queryService    *QueryService
	trustService    *TrustService
	modelService    *ModelManagementService
	reportService   *ForensicReportService
	trainingService *TrainingService
}

func NewHandler(
	assetService *AssetService,
	analysisService *AnalysisService,
	queryService *QueryService,
	trustService *TrustService,
	modelService *ModelManagementService,
	reportService *ForensicReportService,
	trainingService *TrainingService,
) (*Handler, error) {
	if assetService == nil ||
		!assetService.isAvailable() ||
		analysisService == nil ||
		!analysisService.isAvailable() ||
		queryService == nil ||
		!queryService.isAvailable() ||
		trustService == nil ||
		!trustService.isAvailable() ||
		modelService == nil ||
		!modelService.isAvailable() ||
		reportService == nil ||
		trainingService == nil ||
		!trainingService.isAvailable() {
		return nil, errors.New(
			"deepfake forensics handler dependencies are unavailable",
		)
	}

	return &Handler{
		assetService:    assetService,
		analysisService: analysisService,
		queryService:    queryService,
		trustService:    trustService,
		modelService:    modelService,
		reportService:   reportService,
		trainingService: trainingService,
	}, nil
}

// UploadMediaAsset accepts one multipart file under the
// form field named "file".
func (h *Handler) UploadMediaAsset(
	c *gin.Context,
) {
	organizationID, userID, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	fileHeader, err := c.FormFile("file")
	if err != nil {
		response.BadRequest(
			c,
			"Media file is required",
			nil,
		)
		return
	}

	if fileHeader.Size <= 0 {
		response.BadRequest(
			c,
			"Media file is empty",
			nil,
		)
		return
	}
	if h.assetService.fileManager.maximumBytes > 0 &&
		fileHeader.Size >
			h.assetService.fileManager.maximumBytes {
		response.Error(
			c,
			http.StatusRequestEntityTooLarge,
			"Media file exceeds the configured upload limit",
			nil,
		)
		return
	}

	uploadedFile, err := fileHeader.Open()
	if err != nil {
		_ = c.Error(err)
		response.InternalServerError(
			c,
			"Unable to open uploaded media file",
			nil,
		)
		return
	}
	defer uploadedFile.Close()

	request := UploadMediaAssetRequest{
		DepartmentID: strings.TrimSpace(
			c.PostForm("department_id"),
		),
		IncidentID: strings.TrimSpace(
			c.PostForm("incident_id"),
		),
		SourceType: strings.TrimSpace(
			c.PostForm("source_type"),
		),
		Metadata: strings.TrimSpace(
			c.PostForm("metadata"),
		),
	}

	asset, err := h.assetService.UploadMediaAsset(
		c.Request.Context(),
		organizationID,
		userID,
		fileHeader.Filename,
		fileHeader.Header.Get("Content-Type"),
		uploadedFile,
		request,
	)
	if err != nil {
		if errors.Is(
			err,
			ErrMediaUploadQuarantined,
		) &&
			asset != nil {
			response.Success(
				c,
				http.StatusAccepted,
				"Media upload was isolated because its content did not match the declared file type",
				asset,
			)
			return
		}

		handleMediaAPIError(
			c,
			err,
			"Unable to upload media asset",
		)
		return
	}

	response.Created(
		c,
		"Media asset uploaded successfully",
		asset,
	)
}

func (h *Handler) GetMediaAsset(
	c *gin.Context,
) {
	organizationID, _, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	mediaAssetID, ok := handlerPathUUID(
		c,
		"media_asset_id",
	)
	if !ok {
		response.BadRequest(
			c,
			"Invalid media asset ID",
			nil,
		)
		return
	}

	asset, err := h.queryService.GetMediaAsset(
		c.Request.Context(),
		organizationID,
		mediaAssetID,
	)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to retrieve media asset",
		)
		return
	}

	response.OK(
		c,
		"Media asset retrieved successfully",
		asset,
	)
}

func (h *Handler) ListMediaAssets(
	c *gin.Context,
) {
	organizationID, _, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	page, pageSize, ok :=
		parseHandlerPagination(c)
	if !ok {
		return
	}

	incidentID, ok := handlerOptionalQueryUUID(
		c,
		"incident_id",
	)
	if !ok {
		return
	}

	uploadedBy, ok := handlerOptionalQueryUUID(
		c,
		"uploaded_by",
	)
	if !ok {
		return
	}

	createdFrom, ok := handlerOptionalQueryTime(
		c,
		"created_from",
	)
	if !ok {
		return
	}

	createdTo, ok := handlerOptionalQueryTime(
		c,
		"created_to",
	)
	if !ok {
		return
	}

	result, err := h.queryService.ListMediaAssets(
		c.Request.Context(),
		organizationID,
		MediaAssetListFilter{
			MediaType: strings.TrimSpace(
				c.Query("media_type"),
			),
			Status: strings.TrimSpace(
				c.Query("status"),
			),
			SourceType: strings.TrimSpace(
				c.Query("source_type"),
			),

			IncidentID: incidentID,
			UploadedBy: uploadedBy,

			CreatedFrom: createdFrom,
			CreatedTo:   createdTo,

			Limit: pageSize,
			Offset: (page - 1) *
				pageSize,
		},
	)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to list media assets",
		)
		return
	}

	response.OK(
		c,
		"Media assets retrieved successfully",
		result,
	)
}

func (h *Handler) StartMediaAnalysis(
	c *gin.Context,
) {
	organizationID, userID, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	mediaAssetID, ok := handlerPathUUID(
		c,
		"media_asset_id",
	)
	if !ok {
		response.BadRequest(
			c,
			"Invalid media asset ID",
			nil,
		)
		return
	}

	var request StartMediaAnalysisRequest
	if err := c.ShouldBindJSON(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid media analysis request",
			err.Error(),
		)
		return
	}

	result, err :=
		h.analysisService.StartMediaAnalysis(
			c.Request.Context(),
			organizationID,
			mediaAssetID,
			userID,
			request,
		)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to start media analysis",
		)
		return
	}

	response.Success(
		c,
		http.StatusAccepted,
		"Media analysis jobs accepted successfully",
		result,
	)
}

func (h *Handler) GetAnalysisJob(
	c *gin.Context,
) {
	organizationID, _, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	analysisJobID, ok := handlerPathUUID(
		c,
		"analysis_job_id",
	)
	if !ok {
		response.BadRequest(
			c,
			"Invalid analysis job ID",
			nil,
		)
		return
	}

	job, err := h.queryService.GetAnalysisJob(
		c.Request.Context(),
		organizationID,
		analysisJobID,
	)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to retrieve analysis job",
		)
		return
	}

	response.OK(
		c,
		"Media analysis job retrieved successfully",
		job,
	)
}

func (h *Handler) ListAnalysisJobs(
	c *gin.Context,
) {
	organizationID, _, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	page, pageSize, ok :=
		parseHandlerPagination(c)
	if !ok {
		return
	}

	mediaAssetID, ok :=
		handlerOptionalQueryUUID(
			c,
			"media_asset_id",
		)
	if !ok {
		return
	}

	createdFrom, ok := handlerOptionalQueryTime(
		c,
		"created_from",
	)
	if !ok {
		return
	}

	createdTo, ok := handlerOptionalQueryTime(
		c,
		"created_to",
	)
	if !ok {
		return
	}

	result, err :=
		h.queryService.ListAnalysisJobs(
			c.Request.Context(),
			organizationID,
			AnalysisJobListFilter{
				MediaAssetID: mediaAssetID,

				JobType: strings.TrimSpace(
					c.Query("job_type"),
				),
				Status: strings.TrimSpace(
					c.Query("status"),
				),
				Priority: strings.TrimSpace(
					c.Query("priority"),
				),

				CreatedFrom: createdFrom,
				CreatedTo:   createdTo,

				Limit: pageSize,
				Offset: (page - 1) *
					pageSize,
			},
		)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to list media analysis jobs",
		)
		return
	}

	response.OK(
		c,
		"Media analysis jobs retrieved successfully",
		result,
	)
}

func (h *Handler) GetAnalysisResult(
	c *gin.Context,
) {
	organizationID, _, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	analysisJobID, ok := handlerPathUUID(
		c,
		"analysis_job_id",
	)
	if !ok {
		response.BadRequest(
			c,
			"Invalid analysis job ID",
			nil,
		)
		return
	}

	result, err :=
		h.queryService.GetAnalysisResult(
			c.Request.Context(),
			organizationID,
			analysisJobID,
		)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to retrieve media analysis result",
		)
		return
	}

	response.OK(
		c,
		"Media analysis result retrieved successfully",
		result,
	)
}

func (h *Handler) CancelAnalysisJob(
	c *gin.Context,
) {
	organizationID, _, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	analysisJobID, ok := handlerPathUUID(
		c,
		"analysis_job_id",
	)
	if !ok {
		response.BadRequest(
			c,
			"Invalid analysis job ID",
			nil,
		)
		return
	}

	job, err :=
		h.analysisService.CancelAnalysisJob(
			c.Request.Context(),
			organizationID,
			analysisJobID,
		)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to cancel media analysis job",
		)
		return
	}

	response.OK(
		c,
		"Media analysis job cancelled successfully",
		job,
	)
}

func (h *Handler) authenticatedIdentity(
	c *gin.Context,
) (uuid.UUID, uuid.UUID, bool) {
	if h == nil ||
		h.assetService == nil ||
		h.analysisService == nil ||
		h.queryService == nil ||
		h.trustService == nil ||
		h.modelService == nil ||
		h.reportService == nil {
		response.InternalServerError(
			c,
			"Deepfake forensics handler is unavailable",
			nil,
		)
		return uuid.Nil, uuid.Nil, false
	}

	organizationID, ok := handlerContextUUID(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return uuid.Nil, uuid.Nil, false
	}

	userID, ok := handlerContextUUID(
		c,
		"user_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return uuid.Nil, uuid.Nil, false
	}

	return organizationID, userID, true
}

func (s *AnalysisService) CancelAnalysisJob(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*AIAnalysisJob, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		analysisJobID == uuid.Nil {
		return nil, ErrInvalidAnalysisRequest
	}

	return s.repository.CancelAnalysisJob(
		ctx,
		organizationID,
		analysisJobID,
	)
}

func handlerContextUUID(
	c *gin.Context,
	key string,
) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}

	value, exists := c.Get(key)
	if !exists || value == nil {
		return uuid.Nil, false
	}

	switch typedValue := value.(type) {
	case uuid.UUID:
		if typedValue == uuid.Nil {
			return uuid.Nil, false
		}
		return typedValue, true

	case *uuid.UUID:
		if typedValue == nil ||
			*typedValue == uuid.Nil {
			return uuid.Nil, false
		}
		return *typedValue, true

	case string:
		parsedValue, err := uuid.Parse(
			strings.TrimSpace(typedValue),
		)
		if err != nil ||
			parsedValue == uuid.Nil {
			return uuid.Nil, false
		}
		return parsedValue, true

	default:
		return uuid.Nil, false
	}
}

func handlerPathUUID(
	c *gin.Context,
	parameterName string,
) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}

	value, err := uuid.Parse(
		strings.TrimSpace(
			c.Param(parameterName),
		),
	)
	if err != nil || value == uuid.Nil {
		return uuid.Nil, false
	}

	return value, true
}

func parseHandlerPagination(
	c *gin.Context,
) (int, int, bool) {
	page, ok := parsePositiveHandlerQueryInteger(
		c,
		"page",
		1,
		1_000_000,
	)
	if !ok {
		return 0, 0, false
	}

	pageSize, ok :=
		parsePositiveHandlerQueryInteger(
			c,
			"page_size",
			defaultMediaQueryPageSize,
			maximumMediaQueryPageSize,
		)
	if !ok {
		return 0, 0, false
	}

	return page, pageSize, true
}

func parsePositiveHandlerQueryInteger(
	c *gin.Context,
	name string,
	defaultValue int,
	maximumValue int,
) (int, bool) {
	rawValue := strings.TrimSpace(
		c.Query(name),
	)
	if rawValue == "" {
		return defaultValue, true
	}

	value, err := strconv.Atoi(rawValue)
	if err != nil ||
		value <= 0 ||
		value > maximumValue {
		response.BadRequest(
			c,
			fmt.Sprintf(
				"%s must be between 1 and %d",
				name,
				maximumValue,
			),
			nil,
		)
		return 0, false
	}

	return value, true
}

func handlerOptionalQueryUUID(
	c *gin.Context,
	name string,
) (*uuid.UUID, bool) {
	rawValue := strings.TrimSpace(
		c.Query(name),
	)
	if rawValue == "" {
		return nil, true
	}

	value, err := uuid.Parse(rawValue)
	if err != nil || value == uuid.Nil {
		response.BadRequest(
			c,
			fmt.Sprintf(
				"Invalid %s",
				name,
			),
			nil,
		)
		return nil, false
	}

	return &value, true
}

func handlerOptionalQueryTime(
	c *gin.Context,
	name string,
) (*time.Time, bool) {
	rawValue := strings.TrimSpace(
		c.Query(name),
	)
	if rawValue == "" {
		return nil, true
	}

	value, err := time.Parse(
		time.RFC3339,
		rawValue,
	)
	if err != nil {
		response.BadRequest(
			c,
			fmt.Sprintf(
				"%s must use RFC3339 format",
				name,
			),
			nil,
		)
		return nil, false
	}

	value = value.UTC()
	return &value, true
}

func handleMediaAPIError(
	c *gin.Context,
	err error,
	defaultMessage string,
) {
	switch {
	case errors.Is(
		err,
		ErrMediaAssetNotFound,
	),
		errors.Is(
			err,
			ErrAnalysisJobNotFound,
		),
		errors.Is(
			err,
			ErrAnalysisResultNotFound,
		),
		errors.Is(
			err,
			ErrMediaTrustAssessmentNotFound,
		):
		response.NotFound(
			c,
			"Media analysis resource not found",
			nil,
		)

	case errors.Is(
		err,
		ErrMediaUploadTooLarge,
	):
		response.Error(
			c,
			http.StatusRequestEntityTooLarge,
			"Media file exceeds the configured upload limit",
			nil,
		)

	case errors.Is(
		err,
		ErrInvalidMediaUpload,
	),
		errors.Is(
			err,
			ErrUnsupportedMediaUpload,
		),
		errors.Is(
			err,
			ErrInvalidAnalysisRequest,
		),
		errors.Is(
			err,
			ErrUnsupportedAnalysisMode,
		),
		errors.Is(
			err,
			ErrInvalidRepositoryInput,
		),
		errors.Is(
			err,
			ErrInsufficientMediaTrustEvidence,
		):
		response.BadRequest(
			c,
			defaultMessage,
			err.Error(),
		)

	case errors.Is(
		err,
		ErrMediaAssetConflict,
	),
		errors.Is(
			err,
			ErrAnalysisJobConflict,
		):
		response.Error(
			c,
			http.StatusConflict,
			defaultMessage,
			nil,
		)

	case errors.Is(
		err,
		ErrAnalysisModelNotFound,
	):
		response.Error(
			c,
			http.StatusUnprocessableEntity,
			"No compatible organization analysis model is registered",
			nil,
		)

	case errors.Is(
		err,
		ErrAnalysisModelActivationRejected,
	):
		response.Error(
			c,
			http.StatusUnprocessableEntity,
			"AI model version is not ready for activation",
			err.Error(),
		)

	case errors.Is(
		err,
		ErrMediaStorageIntegrity,
	):
		response.Error(
			c,
			http.StatusUnprocessableEntity,
			"Media storage integrity verification failed",
			nil,
		)

	case errors.Is(
		err,
		ErrMediaEngineUnavailable,
	):
		response.Error(
			c,
			http.StatusServiceUnavailable,
			"Offline media analysis engine is unavailable",
			nil,
		)

	case errors.Is(
		err,
		context.Canceled,
	),
		errors.Is(
			err,
			context.DeadlineExceeded,
		):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Media analysis request timed out",
			nil,
		)

	default:
		_ = c.Error(err)
		errPayload := interface{}(nil)
		if err != nil {
			errPayload = err.Error()
		}
		response.InternalServerError(
			c,
			defaultMessage,
			errPayload,
		)
	}
}
