package deepfakeforensics

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

func (h *Handler) QuarantineMediaAsset(
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

	var request MediaAssetQuarantineRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid media quarantine request",
			err.Error(),
		)
		return
	}

	asset, err :=
		h.assetService.QuarantineMediaAsset(
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
			"Unable to quarantine media asset",
		)
		return
	}

	response.OK(
		c,
		"Media asset quarantined successfully",
		asset,
	)
}

func (h *Handler) ReleaseMediaAsset(
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

	var request MediaAssetQuarantineRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid media release request",
			err.Error(),
		)
		return
	}

	asset, err := h.assetService.ReleaseMediaAsset(
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
			"Unable to release media asset",
		)
		return
	}

	response.OK(
		c,
		"Media asset released from quarantine successfully",
		asset,
	)
}

func (h *Handler) RetryAnalysisJob(
	c *gin.Context,
) {
	organizationID, userID, ok :=
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

	job, err := h.analysisService.RetryAnalysisJob(
		c.Request.Context(),
		organizationID,
		analysisJobID,
		userID,
	)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to retry media analysis job",
		)
		return
	}

	response.Success(
		c,
		http.StatusAccepted,
		"Media analysis job queued for manual retry",
		job,
	)
}

func (h *Handler) ListMediaAssetSecurityEvents(
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

	page, pageSize, ok :=
		parseHandlerPagination(c)
	if !ok {
		return
	}

	events, err :=
		h.assetService.ListMediaAssetSecurityEvents(
			c.Request.Context(),
			organizationID,
			mediaAssetID,
			page,
			pageSize,
		)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to retrieve media security events",
		)
		return
	}

	response.OK(
		c,
		"Media security events retrieved successfully",
		events,
	)
}

func (h *Handler) GetMediaTrustAssessment(
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

	assessment, err :=
		h.trustService.GetMediaTrustAssessment(
			c.Request.Context(),
			organizationID,
			mediaAssetID,
		)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to retrieve media trust assessment",
		)
		return
	}

	response.OK(
		c,
		"Media trust assessment retrieved successfully",
		assessment,
	)
}

func (h *Handler) RecalculateMediaTrustAssessment(
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

	assessment, err :=
		h.trustService.RecalculateMediaTrustAssessment(
			c.Request.Context(),
			organizationID,
			mediaAssetID,
		)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to recalculate media trust assessment",
		)
		return
	}

	response.OK(
		c,
		"Media trust assessment recalculated successfully",
		assessment,
	)
}

func (h *Handler) ListManagedAIModels(
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

	result, err := h.modelService.ListModels(
		c.Request.Context(),
		organizationID,
		ManagedAIModelFilter{
			ModelType: strings.TrimSpace(
				c.Query("model_type"),
			),
			Status: strings.TrimSpace(
				c.Query("status"),
			),
			Limit:  pageSize,
			Offset: (page - 1) * pageSize,
		},
	)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to list media analysis models",
		)
		return
	}

	response.OK(
		c,
		"Media analysis models retrieved successfully",
		result,
	)
}

func (h *Handler) GetManagedAIModel(
	c *gin.Context,
) {
	organizationID, _, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	modelID, ok := handlerPathUUID(c, "model_id")
	if !ok {
		response.BadRequest(
			c,
			"Invalid AI model ID",
			nil,
		)
		return
	}

	model, err := h.modelService.GetModel(
		c.Request.Context(),
		organizationID,
		modelID,
	)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to retrieve media analysis model",
		)
		return
	}

	response.OK(
		c,
		"Media analysis model retrieved successfully",
		model,
	)
}

func (h *Handler) UploadManagedAIModel(
	c *gin.Context,
) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}

	fileHeader, err := c.FormFile("file")
	if err != nil {
		response.BadRequest(c, "Model file is required", nil)
		return
	}
	if fileHeader.Size <= 0 {
		response.BadRequest(c, "Model file is empty", nil)
		return
	}

	uploadedFile, err := fileHeader.Open()
	if err != nil {
		response.InternalServerError(c, "Unable to open uploaded model file", nil)
		return
	}
	defer uploadedFile.Close()

	request := UploadAIModelRequest{
		ModelCode:           strings.TrimSpace(c.PostForm("model_code")),
		ModelName:           strings.TrimSpace(c.PostForm("model_name")),
		ModelType:           strings.TrimSpace(c.PostForm("model_type")),
		Framework:           strings.TrimSpace(c.PostForm("framework")),
		VersionNumber:       strings.TrimSpace(c.PostForm("version_number")),
		Description:         strings.TrimSpace(c.PostForm("description")),
		SupportsCPU:         parseBoolForm(c.PostForm("supports_cpu")),
		SupportsGPU:         parseBoolForm(c.PostForm("supports_gpu")),
		ConfidenceThreshold: parseFloatForm(c.PostForm("confidence_threshold")),
		TrainingDatasetName: strings.TrimSpace(c.PostForm("training_dataset_name")),
		ValidationAccuracy:  parseFloatForm(c.PostForm("validation_accuracy")),
		PrecisionScore:      parseFloatForm(c.PostForm("precision_score")),
		RecallScore:         parseFloatForm(c.PostForm("recall_score")),
		F1Score:             parseFloatForm(c.PostForm("f1_score")),
	}

	result, err := h.modelService.UploadModel(c.Request.Context(), organizationID, userID, request, uploadedFile, fileHeader.Filename)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to upload AI model")
		return
	}

	response.Created(c, "AI model uploaded and registered successfully", result)
}

func (h *Handler) UploadManagedAIModelVersion(
	c *gin.Context,
) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	modelID, ok := handlerPathUUID(c, "model_id")
	if !ok {
		response.BadRequest(c, "Invalid AI model ID", nil)
		return
	}

	fileHeader, err := c.FormFile("file")
	if err != nil {
		response.BadRequest(c, "Model file is required", nil)
		return
	}
	if fileHeader.Size <= 0 {
		response.BadRequest(c, "Model file is empty", nil)
		return
	}

	uploadedFile, err := fileHeader.Open()
	if err != nil {
		response.InternalServerError(c, "Unable to open uploaded model file", nil)
		return
	}
	defer uploadedFile.Close()

	request := UploadAIModelVersionRequest{
		VersionNumber:       strings.TrimSpace(c.PostForm("version_number")),
		TrainingDatasetName: strings.TrimSpace(c.PostForm("training_dataset_name")),
		ValidationAccuracy:  parseFloatForm(c.PostForm("validation_accuracy")),
		PrecisionScore:      parseFloatForm(c.PostForm("precision_score")),
		RecallScore:         parseFloatForm(c.PostForm("recall_score")),
		F1Score:             parseFloatForm(c.PostForm("f1_score")),
		ConfidenceThreshold: parseFloatForm(c.PostForm("confidence_threshold")),
	}

	result, err := h.modelService.UploadModelVersion(c.Request.Context(), organizationID, userID, modelID, request, uploadedFile, fileHeader.Filename)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to upload AI model version")
		return
	}

	response.Created(c, "AI model version uploaded successfully", result)
}

func (h *Handler) RollbackManagedAIModelVersion(
	c *gin.Context,
) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	modelID, ok := handlerPathUUID(c, "model_id")
	if !ok {
		response.BadRequest(c, "Invalid AI model ID", nil)
		return
	}

	var request RollbackAIModelVersionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid AI model rollback request", err.Error())
		return
	}

	result, err := h.modelService.RollbackVersion(c.Request.Context(), organizationID, modelID, request, userID)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to rollback AI model version")
		return
	}

	response.Success(c, http.StatusOK, "AI model rolled back successfully", result)
}

func (h *Handler) AssignManagedAIModelVersion(
	c *gin.Context,
) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	modelID, ok := handlerPathUUID(c, "model_id")
	if !ok {
		response.BadRequest(c, "Invalid AI model ID", nil)
		return
	}

	var request AssignAIModelVersionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid AI model assignment request", err.Error())
		return
	}

	result, err := h.modelService.AssignModelVersion(c.Request.Context(), organizationID, userID, modelID, request)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to assign AI model version")
		return
	}

	response.Success(c, http.StatusOK, "Organization model assignment created successfully", result)
}

func (h *Handler) ActivateManagedAIModelVersion(
	c *gin.Context,
) {
	organizationID, userID, ok :=
		h.authenticatedIdentity(c)
	if !ok {
		return
	}

	modelID, ok := handlerPathUUID(c, "model_id")
	if !ok {
		response.BadRequest(
			c,
			"Invalid AI model ID",
			nil,
		)
		return
	}
	versionID, ok := handlerPathUUID(
		c,
		"model_version_id",
	)
	if !ok {
		response.BadRequest(
			c,
			"Invalid AI model version ID",
			nil,
		)
		return
	}

	var request ActivateAIModelVersionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid AI model activation request",
			err.Error(),
		)
		return
	}

	model, err := h.modelService.ActivateVersion(
		c.Request.Context(),
		organizationID,
		modelID,
		versionID,
		userID,
		request,
	)
	if err != nil {
		handleMediaAPIError(
			c,
			err,
			"Unable to activate AI model version",
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"AI model version activated successfully",
		model,
	)
}
