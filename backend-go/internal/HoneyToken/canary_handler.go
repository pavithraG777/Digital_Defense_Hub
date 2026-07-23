package honeytoken

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

type CanaryHandler struct {
	service *CanaryService
}

func NewCanaryHandler(
	service *CanaryService,
) *CanaryHandler {
	return &CanaryHandler{
		service: service,
	}
}

func (h *CanaryHandler) CreateCanaryFile(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := canaryUUIDFromContext(
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

	createdBy, ok := canaryUUIDFromContext(
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

	var request CreateCanaryFileRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	if err := validateCanaryCreateRequest(request); err != nil {
		response.BadRequest(
			c,
			"Invalid canary file request",
			err.Error(),
		)
		return
	}

	createdCanary, err := h.service.CreateCanaryFile(
		c.Request.Context(),
		organizationID,
		createdBy,
		request,
	)
	if err != nil {
		handleCreateCanaryFileError(c, err)
		return
	}

	response.Created(
		c,
		"Canary file created successfully",
		createdCanary,
	)
}

func (h *CanaryHandler) GetCanaryFile(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := canaryUUIDFromContext(
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

	canaryID := strings.TrimSpace(c.Param("id"))

	if _, err := uuid.Parse(canaryID); err != nil {
		response.BadRequest(
			c,
			"Invalid canary file ID",
			err.Error(),
		)
		return
	}

	canary, err := h.service.GetCanaryFile(
		c.Request.Context(),
		organizationID,
		canaryID,
	)
	if err != nil {
		handleGetCanaryFileError(c, err)
		return
	}

	response.OK(
		c,
		"Canary file retrieved successfully",
		canary,
	)
}

func (h *CanaryHandler) ListCanaryFiles(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := canaryUUIDFromContext(
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

	var request ListCanaryFilesRequest

	if err := c.ShouldBindQuery(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid canary file filters",
			err.Error(),
		)
		return
	}

	canaryFiles, err := h.service.ListCanaryFiles(
		c.Request.Context(),
		organizationID,
		request,
	)
	if err != nil {
		handleListCanaryFilesError(c, err)
		return
	}

	response.OK(
		c,
		"Canary files retrieved successfully",
		canaryFiles,
	)
}

func (h *CanaryHandler) DeployCanaryFile(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Canary handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := canaryUUIDFromContext(
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

	canaryID := strings.TrimSpace(c.Param("id"))

	if _, err := uuid.Parse(canaryID); err != nil {
		response.BadRequest(
			c,
			"Invalid canary file ID",
			err.Error(),
		)
		return
	}

	var request DeployCanaryFileRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	createdDeployment, err :=
		h.service.DeployCanaryFile(
			c.Request.Context(),
			organizationID,
			canaryID,
			request,
		)
	if err != nil {
		handleDeployCanaryFileError(c, err)
		return
	}

	response.OK(
		c,
		"Canary file deployed successfully",
		createdDeployment,
	)
}

func (h *CanaryHandler) isAvailable() bool {
	return h != nil && h.service != nil
}

func canaryUUIDFromContext(
	c *gin.Context,
	key string,
) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}

	value, exists := c.Get(key)
	if !exists {
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

func validateCanaryCreateRequest(
	request CreateCanaryFileRequest,
) error {
	if request.ContainsHoneytoken &&
		request.HoneytokenID == nil {
		return ErrCanaryHoneytokenRequired
	}

	if !request.ContainsHoneytoken &&
		request.HoneytokenID != nil {
		return ErrCanaryUnexpectedHoneytoken
	}

	if request.ExpiresAt == nil ||
		strings.TrimSpace(*request.ExpiresAt) == "" {
		return nil
	}

	expiresAt, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(*request.ExpiresAt),
	)
	if err != nil {
		return errors.New(
			"expires_at must use RFC3339 format",
		)
	}

	if !expiresAt.After(time.Now().UTC()) {
		return ErrCanaryFileExpired
	}

	return nil
}

func handleCreateCanaryFileError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrInvalidCanaryFileName),
		errors.Is(err, ErrUnsupportedCanaryType),
		errors.Is(err, ErrCanaryHoneytokenRequired),
		errors.Is(err, ErrCanaryUnexpectedHoneytoken),
		errors.Is(err, ErrCanaryLinkedHoneytokenUnavailable),
		errors.Is(err, ErrCanaryFileExpired):
		response.BadRequest(
			c,
			"Invalid canary file request",
			err.Error(),
		)

	case errors.Is(err, ErrCanaryDepartmentNotFound),
		errors.Is(err, ErrCanaryPolicyNotFound),
		errors.Is(err, ErrCanaryHoneytokenNotFound),
		errors.Is(err, ErrCanaryOwnerNotFound),
		errors.Is(err, ErrCanaryCreatorNotFound):
		response.BadRequest(
			c,
			"Referenced resource is unavailable",
			nil,
		)

	case errors.Is(err, ErrCanaryFileCodeExists),
		errors.Is(err, ErrCanaryFilePathExists),
		errors.Is(err, ErrCanaryTrackingIdentifierExists):
		response.Error(
			c,
			http.StatusConflict,
			"Canary file already exists",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Canary file creation timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to create canary file",
			nil,
		)
	}
}

func handleGetCanaryFileError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrCanaryFileNotFound):
		response.NotFound(
			c,
			"Canary file not found",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Canary file request timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to retrieve canary file",
			nil,
		)
	}
}

func handleListCanaryFilesError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrUnsupportedCanaryType):
		response.BadRequest(
			c,
			"Invalid canary file filters",
			err.Error(),
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Canary file request timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to retrieve canary files",
			nil,
		)
	}
}

func handleDeployCanaryFileError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrCanaryFileNotFound):
		response.NotFound(
			c,
			"Canary file not found",
			nil,
		)

	case errors.Is(err, ErrCanaryDeploymentOutsideRoot):
		response.Forbidden(
			c,
			"Canary deployment location is not allowed",
			nil,
		)

	case errors.Is(err, ErrCanaryFileExpired),
		errors.Is(err, ErrCanaryFileNotDeployable):
		response.Error(
			c,
			http.StatusConflict,
			"Canary file cannot be deployed",
			err.Error(),
		)

	case errors.Is(err, ErrCanaryDeploymentFileExists),
		errors.Is(err, ErrCanaryFilePathExists):
		response.Error(
			c,
			http.StatusConflict,
			"Canary deployment file already exists",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Canary file deployment timed out",
			nil,
		)

	case errors.Is(
		err,
		ErrCanaryIntegrityVerificationFailed,
	):
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Canary file integrity verification failed",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to deploy canary file",
			nil,
		)
	}
}
