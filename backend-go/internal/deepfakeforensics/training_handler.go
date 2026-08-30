package deepfakeforensics

import (
	"github.com/gin-gonic/gin"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"net/http"
)

func (h *Handler) RegisterTrainingDatasetVersion(c *gin.Context) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	datasetID, ok := handlerPathUUID(c, "dataset_id")
	if !ok {
		response.BadRequest(c, "Invalid training dataset ID", nil)
		return
	}
	var request RegisterTrainingDatasetVersionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid training dataset version request", err.Error())
		return
	}
	version, err := h.trainingService.RegisterDatasetVersion(c.Request.Context(), organizationID, userID, datasetID, request)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to register training dataset version")
		return
	}
	response.Created(c, "Training dataset version registered successfully", version)
}

func (h *Handler) ValidateTrainingDatasetVersion(c *gin.Context) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	datasetID, ok := handlerPathUUID(c, "dataset_id")
	if !ok {
		response.BadRequest(c, "Invalid training dataset ID", nil)
		return
	}
	versionID, ok := handlerPathUUID(c, "dataset_version_id")
	if !ok {
		response.BadRequest(c, "Invalid training dataset version ID", nil)
		return
	}
	var request ValidateTrainingDatasetVersionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid dataset validation request", err.Error())
		return
	}
	version, err := h.trainingService.ValidateDatasetVersion(c.Request.Context(), organizationID, userID, datasetID, versionID, request)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to validate training dataset version")
		return
	}
	response.OK(c, "Training dataset version validation completed", version)
}

func (h *Handler) RegisterTrainingDataset(c *gin.Context) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	var request RegisterTrainingDatasetRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid training dataset request", err.Error())
		return
	}
	dataset, err := h.trainingService.RegisterDataset(c.Request.Context(), organizationID, userID, request)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to register training dataset")
		return
	}
	response.Created(c, "Training dataset registered successfully", dataset)
}
func (h *Handler) ListTrainingDatasets(c *gin.Context) {
	organizationID, _, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	page, pageSize, ok := parseHandlerPagination(c)
	if !ok {
		return
	}
	result, err := h.trainingService.ListDatasets(c.Request.Context(), organizationID, page, pageSize)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to list training datasets")
		return
	}
	response.OK(c, "Training datasets retrieved successfully", result)
}
func (h *Handler) CreateTrainingJob(c *gin.Context) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	var request CreateTrainingJobRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid training job request", err.Error())
		return
	}
	job, err := h.trainingService.CreateJob(c.Request.Context(), organizationID, userID, request)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to create training job")
		return
	}
	response.Success(c, http.StatusAccepted, "Training job queued successfully", job)
}
func (h *Handler) ListTrainingJobs(c *gin.Context) {
	organizationID, _, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	page, pageSize, ok := parseHandlerPagination(c)
	if !ok {
		return
	}
	result, err := h.trainingService.ListJobs(c.Request.Context(), organizationID, page, pageSize)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to list training jobs")
		return
	}
	response.OK(c, "Training jobs retrieved successfully", result)
}

func (h *Handler) GetTrainingJob(c *gin.Context) {
	organizationID, _, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	jobID, ok := handlerPathUUID(c, "training_job_id")
	if !ok {
		response.BadRequest(c, "Invalid training job ID", nil)
		return
	}
	job, err := h.trainingService.GetJob(c.Request.Context(), organizationID, jobID)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to retrieve training job")
		return
	}
	response.OK(c, "Training job retrieved successfully", job)
}

func (h *Handler) CancelTrainingJob(c *gin.Context) {
	organizationID, _, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	jobID, ok := handlerPathUUID(c, "training_job_id")
	if !ok {
		response.BadRequest(c, "Invalid training job ID", nil)
		return
	}
	job, err := h.trainingService.CancelJob(c.Request.Context(), organizationID, jobID)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to cancel training job")
		return
	}
	response.OK(c, "Training job cancelled successfully", job)
}

func (h *Handler) DecideTrainingApproval(c *gin.Context) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	jobID, ok := handlerPathUUID(c, "training_job_id")
	if !ok {
		response.BadRequest(c, "Invalid training job ID", nil)
		return
	}
	var request DecideTrainingApprovalRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid training approval request", err.Error())
		return
	}
	result, err := h.trainingService.DecideApproval(c.Request.Context(), organizationID, userID, jobID, request)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to decide training approval")
		return
	}
	response.OK(c, "Training approval decision recorded", result)
}
