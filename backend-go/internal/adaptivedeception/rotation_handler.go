package adaptivedeception

import (
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

// RotationHandler exposes authenticated dynamic
// canary rotation endpoints.
type RotationHandler struct {
	service *RotationService
}

func NewRotationHandler(
	service *RotationService,
) *RotationHandler {
	return &RotationHandler{
		service: service,
	}
}

func (h *RotationHandler) RotateCanary(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary rotation handler is unavailable",
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

	requestedBy, ok :=
		adaptiveContextUUID(
			c,
			"user_id",
		)
	if !ok {
		response.Unauthorized(
			c,
			"Authenticated user information is missing",
			nil,
		)
		return
	}

	canaryFileID, ok :=
		adaptivePathUUID(
			c,
			"canary_file_id",
		)
	if !ok {
		response.BadRequest(
			c,
			"Invalid canary file ID",
			nil,
		)
		return
	}

	var request RotateCanaryRequest

	if err := c.ShouldBindJSON(
		&request,
	); err != nil &&
		!errors.Is(err, io.EOF) {
		response.BadRequest(
			c,
			"Invalid canary rotation request",
			err.Error(),
		)
		return
	}

	rotation, err :=
		h.service.RotateCanary(
			c.Request.Context(),
			organizationID,
			canaryFileID,
			RotationCommand{
				RotationReason: request.RotationReason,

				RotationStrategy: request.RotationStrategy,

				NewFileName: request.NewFileName,

				RequestedBy: &requestedBy,
			},
		)
	if err != nil {
		handleCanaryRotationError(
			c,
			err,
		)
		return
	}

	response.OK(
		c,
		"Canary rotated successfully",
		rotation,
	)
}

func (h *RotationHandler) GetRotation(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary rotation handler is unavailable",
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

	rotationID, ok :=
		adaptivePathUUID(
			c,
			"rotation_id",
		)
	if !ok {
		response.BadRequest(
			c,
			"Invalid canary rotation ID",
			nil,
		)
		return
	}

	rotation, err :=
		h.service.GetRotation(
			c.Request.Context(),
			organizationID,
			rotationID,
		)
	if err != nil {
		handleCanaryRotationError(
			c,
			err,
		)
		return
	}

	response.OK(
		c,
		"Canary rotation retrieved successfully",
		rotation,
	)
}

func (h *RotationHandler) isAvailable() bool {
	return h != nil &&
		h.service != nil
}

func handleCanaryRotationError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(
		err,
		ErrCanaryFileNotFound,
	):
		response.NotFound(
			c,
			"Canary file not found",
			nil,
		)

	case errors.Is(
		err,
		ErrCanaryRotationNotFound,
	):
		response.NotFound(
			c,
			"Canary rotation not found",
			nil,
		)

	case errors.Is(
		err,
		ErrActiveCanaryRotationExists,
	):
		c.JSON(
			http.StatusConflict,
			gin.H{
				"success": false,
				"message": "An active canary rotation already exists",
				"data":    nil,
			},
		)

	case errors.Is(
		err,
		ErrInvalidCanaryRotationRequest,
	), errors.Is(
		err,
		ErrInvalidCanaryRotationState,
	):
		response.BadRequest(
			c,
			"Invalid canary rotation request",
			err.Error(),
		)

	default:
		response.InternalServerError(
			c,
			"Unable to rotate canary file",
			nil,
		)
	}
}
