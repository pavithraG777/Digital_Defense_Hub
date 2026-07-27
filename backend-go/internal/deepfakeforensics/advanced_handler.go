package deepfakeforensics

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

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
