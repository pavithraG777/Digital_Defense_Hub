package adaptivedeception

import (
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

// FingerprintHandler exposes authenticated canary
// interaction fingerprint query APIs.
type FingerprintHandler struct {
	service *FingerprintQueryService
}

func NewFingerprintHandler(
	service *FingerprintQueryService,
) *FingerprintHandler {
	return &FingerprintHandler{
		service: service,
	}
}

func (h *FingerprintHandler) ListFingerprints(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary fingerprint handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok :=
		adaptiveContextUUID(
			c,
			"organization_id",
		)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	var request ListFingerprintsRequest

	if err := c.ShouldBindQuery(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid canary fingerprint filters",
			err.Error(),
		)
		return
	}

	result, err :=
		h.service.ListFingerprints(
			c.Request.Context(),
			organizationID,
			request,
		)
	if err != nil {
		handleCanaryFingerprintError(
			c,
			err,
		)
		return
	}

	response.OK(
		c,
		"Canary interaction fingerprints retrieved successfully",
		result,
	)
}

func (h *FingerprintHandler) GetFingerprint(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary fingerprint handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok :=
		adaptiveContextUUID(
			c,
			"organization_id",
		)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	fingerprintID, ok :=
		adaptivePathUUID(
			c,
			"fingerprint_id",
		)
	if !ok {
		response.BadRequest(
			c,
			"Invalid fingerprint ID",
			nil,
		)
		return
	}

	fingerprint, err :=
		h.service.GetFingerprint(
			c.Request.Context(),
			organizationID,
			fingerprintID.String(),
		)
	if err != nil {
		handleCanaryFingerprintError(
			c,
			err,
		)
		return
	}

	response.OK(
		c,
		"Canary interaction fingerprint retrieved successfully",
		fingerprint,
	)
}

func (h *FingerprintHandler) isAvailable() bool {
	return h != nil &&
		h.service != nil
}

func handleCanaryFingerprintError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(
		err,
		ErrCanaryFingerprintNotFound,
	):
		response.NotFound(
			c,
			"Canary interaction fingerprint not found",
			nil,
		)

	case errors.Is(
		err,
		ErrInvalidCanaryFingerprintQuery,
	):
		response.BadRequest(
			c,
			"Invalid canary fingerprint query",
			err.Error(),
		)

	default:
		response.InternalServerError(
			c,
			"Unable to process canary fingerprint request",
			nil,
		)
	}
}
