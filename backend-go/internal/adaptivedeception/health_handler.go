package adaptivedeception

import (
	"errors"
	"io"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

// HealthHandler exposes authenticated canary health APIs.
type HealthHandler struct {
	service *HealthService
}

func NewHealthHandler(
	service *HealthService,
) *HealthHandler {
	return &HealthHandler{
		service: service,
	}
}

func (h *HealthHandler) CheckCanaryHealth(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary health handler is unavailable",
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

	var request CheckCanaryHealthRequest

	if err := c.ShouldBindJSON(
		&request,
	); err != nil &&
		!errors.Is(err, io.EOF) {
		response.BadRequest(
			c,
			"Invalid canary health check request",
			err.Error(),
		)
		return
	}

	if strings.TrimSpace(
		request.CheckType,
	) == "" {
		request.CheckType =
			HealthCheckTypeManual
	}

	healthCheck, err :=
		h.service.CheckCanaryHealth(
			c.Request.Context(),
			organizationID,
			canaryFileID,
			request.CheckType,
		)
	if err != nil {
		handleCanaryHealthError(
			c,
			err,
		)
		return
	}

	response.OK(
		c,
		"Canary health check completed successfully",
		healthCheck,
	)
}

func (h *HealthHandler) GetCanaryHealth(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary health handler is unavailable",
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

	details, err :=
		h.service.GetCanaryHealthDetails(
			c.Request.Context(),
			organizationID,
			canaryFileID,
		)
	if err != nil {
		handleCanaryHealthError(
			c,
			err,
		)
		return
	}

	response.OK(
		c,
		"Canary health details retrieved successfully",
		details,
	)
}

func (h *HealthHandler) isAvailable() bool {
	return h != nil &&
		h.service != nil
}

func handleCanaryHealthError(
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
		ErrCanaryHealthCheckNotFound,
	):
		response.NotFound(
			c,
			"Canary health check not found",
			nil,
		)

	case errors.Is(
		err,
		ErrInvalidCanaryHealthRequest,
	):
		response.BadRequest(
			c,
			"Invalid canary health check request",
			err.Error(),
		)

	default:
		response.InternalServerError(
			c,
			"Unable to process canary health request",
			nil,
		)
	}
}

func adaptiveContextUUID(
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

func adaptivePathUUID(
	c *gin.Context,
	parameterName string,
) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}

	value := strings.TrimSpace(
		c.Param(parameterName),
	)

	parsedValue, err := uuid.Parse(value)
	if err != nil ||
		parsedValue == uuid.Nil {
		return uuid.Nil, false
	}

	return parsedValue, true
}
