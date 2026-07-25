package preencryption

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

const detectionEngineHealthTimeout = 5 * time.Second

type Handler struct {
	service *Service
}

func NewHandler(
	service *Service,
) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) ListDetections(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Pre-encryption detection handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok :=
		detectionContextUUID(
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

	var query ListDetectionsQuery

	if err := c.ShouldBindQuery(
		&query,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid pre-encryption detection query",
			err.Error(),
		)
		return
	}

	result, err := h.service.ListDetections(
		c.Request.Context(),
		organizationID,
		query,
	)
	if err != nil {
		handleDetectionError(c, err)
		return
	}

	response.OK(
		c,
		"Pre-encryption detections retrieved successfully",
		result,
	)
}

func (h *Handler) GetDetection(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Pre-encryption detection handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok :=
		detectionContextUUID(
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

	detectionID := strings.TrimSpace(
		c.Param("detection_id"),
	)

	detection, err := h.service.GetDetection(
		c.Request.Context(),
		organizationID,
		detectionID,
	)
	if err != nil {
		handleDetectionError(c, err)
		return
	}

	response.OK(
		c,
		"Pre-encryption detection retrieved successfully",
		detection,
	)
}

func (h *Handler) GetDetectionDetails(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Pre-encryption detection handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok :=
		detectionContextUUID(
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

	detectionID := strings.TrimSpace(
		c.Param("detection_id"),
	)

	details, err :=
		h.service.GetDetectionDetails(
			c.Request.Context(),
			organizationID,
			detectionID,
		)
	if err != nil {
		handleDetectionError(c, err)
		return
	}

	response.OK(
		c,
		"Pre-encryption detection details retrieved successfully",
		details,
	)
}

func (h *Handler) UpdateDetectionStatus(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Pre-encryption detection handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok :=
		detectionContextUUID(
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

	userID, ok :=
		detectionContextUUID(
			c,
			"user_id",
		)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return
	}

	detectionID := strings.TrimSpace(
		c.Param("detection_id"),
	)

	var request UpdateDetectionStatusRequest

	if err := c.ShouldBindJSON(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid pre-encryption detection status request",
			err.Error(),
		)
		return
	}

	detection, err :=
		h.service.UpdateDetectionStatus(
			c.Request.Context(),
			organizationID,
			userID,
			detectionID,
			request,
		)
	if err != nil {
		handleDetectionError(c, err)
		return
	}

	response.OK(
		c,
		"Pre-encryption detection status updated successfully",
		detection,
	)
}

func (h *Handler) CheckEngineHealth(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Pre-encryption detection handler is unavailable",
			nil,
		)
		return
	}

	healthContext, cancel :=
		context.WithTimeout(
			c.Request.Context(),
			detectionEngineHealthTimeout,
		)
	defer cancel()

	health, err :=
		h.service.CheckDetectionEngineHealth(
			healthContext,
		)
	if err != nil {
		handleDetectionError(c, err)
		return
	}

	response.OK(
		c,
		"Pre-encryption Detection Engine is healthy",
		health,
	)
}

func (h *Handler) isAvailable() bool {
	return h != nil &&
		h.service != nil
}

func detectionContextUUID(
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
			strings.TrimSpace(
				typedValue,
			),
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

func handleDetectionError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(
		err,
		ErrDetectionNotFound,
	):
		response.NotFound(
			c,
			"Pre-encryption detection not found",
			nil,
		)

	case errors.Is(
		err,
		ErrInvalidDetectionStatusTransition,
	),
		errors.Is(
			err,
			ErrInvalidDetectionActionTransition,
		):
		response.Error(
			c,
			http.StatusConflict,
			"Invalid pre-encryption detection state transition",
			err.Error(),
		)

	case errors.Is(
		err,
		ErrInvalidDetectionWorkflowRequest,
	),
		errors.Is(
			err,
			ErrNoDetectionWorkflowChanges,
		):
		response.BadRequest(
			c,
			"Invalid pre-encryption detection workflow request",
			err.Error(),
		)

	case errors.Is(
		err,
		ErrInvalidDetectionQuery,
	):
		response.BadRequest(
			c,
			"Invalid pre-encryption detection request",
			err.Error(),
		)

	case errors.Is(
		err,
		ErrDetectionEngineUnavailable,
	):
		response.Error(
			c,
			http.StatusServiceUnavailable,
			"Pre-encryption Detection Engine is unavailable",
			nil,
		)

	case errors.Is(
		err,
		ErrInvalidDetectionEngineResponse,
	):
		response.Error(
			c,
			http.StatusBadGateway,
			"Pre-encryption Detection Engine returned an invalid response",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Pre-encryption detection operation failed",
			nil,
		)
	}
}
