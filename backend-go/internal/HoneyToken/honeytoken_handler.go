package honeytoken

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

// HoneytokenHandler exposes organization-scoped honeytoken APIs.
type HoneytokenHandler struct {
	service *HoneytokenService
}

// NewHoneytokenHandler creates the honeytoken HTTP handler.
func NewHoneytokenHandler(
	service *HoneytokenService,
) *HoneytokenHandler {
	return &HoneytokenHandler{
		service: service,
	}
}

// CreateHoneytoken generates and stores one honeytoken.
func (h *HoneytokenHandler) CreateHoneytoken(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Honeytoken handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := honeytokenUUIDFromContext(
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

	createdBy, ok := honeytokenUUIDFromContext(
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

	var request CreateHoneytokenRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid honeytoken request payload",
			err.Error(),
		)
		return
	}

	normalizeCreateHoneytokenRequest(
		&request,
	)

	if err := validateCreateHoneytokenHandlerRequest(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid honeytoken request",
			err.Error(),
		)
		return
	}

	createdToken, err := h.service.CreateHoneytoken(
		c.Request.Context(),
		organizationID,
		createdBy,
		&request,
	)
	if err != nil {
		handleCreateHoneytokenError(
			c,
			err,
		)
		return
	}

	if createdToken == nil {
		internalError := errors.New(
			"honeytoken service returned an empty create result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to create honeytoken",
			nil,
		)
		return
	}

	response.Created(
		c,
		"Honeytoken created successfully",
		createdToken,
	)
}

// GetHoneytoken returns safe metadata for one organization-owned token.
func (h *HoneytokenHandler) GetHoneytoken(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Honeytoken handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := honeytokenUUIDFromContext(
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

	honeytokenID, err := uuid.Parse(
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil || honeytokenID == uuid.Nil {
		response.BadRequest(
			c,
			"Invalid honeytoken ID",
			nil,
		)
		return
	}

	token, err := h.service.GetHoneytoken(
		c.Request.Context(),
		organizationID,
		honeytokenID,
	)
	if err != nil {
		handleGetHoneytokenError(
			c,
			err,
		)
		return
	}

	if token == nil {
		internalError := errors.New(
			"honeytoken service returned an empty result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to retrieve honeytoken",
			nil,
		)
		return
	}

	response.OK(
		c,
		"Honeytoken retrieved successfully",
		token,
	)
}

// ListHoneytokens returns paginated organization-owned metadata.
func (h *HoneytokenHandler) ListHoneytokens(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Honeytoken handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := honeytokenUUIDFromContext(
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

	var request ListHoneytokensRequest

	if err := c.ShouldBindQuery(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid honeytoken query parameters",
			err.Error(),
		)
		return
	}

	normalizeListHoneytokensRequest(
		&request,
	)

	if err := validateListHoneytokensRequest(
		request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid honeytoken query parameters",
			err.Error(),
		)
		return
	}

	if _, err := parseOptionalHoneytokenUUID(
		request.DepartmentID,
		"department ID",
	); err != nil {
		response.BadRequest(
			c,
			"Invalid honeytoken query parameters",
			err.Error(),
		)
		return
	}

	result, err := h.service.ListHoneytokens(
		c.Request.Context(),
		organizationID,
		request,
	)
	if err != nil {
		handleListHoneytokensError(
			c,
			err,
		)
		return
	}

	if result == nil {
		internalError := errors.New(
			"honeytoken service returned an empty list result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to list honeytokens",
			nil,
		)
		return
	}

	response.OK(
		c,
		"Honeytokens retrieved successfully",
		result,
	)
}

func (h *HoneytokenHandler) isAvailable() bool {
	return h != nil && h.service != nil
}

func validateCreateHoneytokenHandlerRequest(
	req *CreateHoneytokenRequest,
) error {
	if err := validateCreateHoneytokenRequest(
		req,
	); err != nil {
		return err
	}

	if _, err := parseOptionalHoneytokenUUID(
		req.DepartmentID,
		"department ID",
	); err != nil {
		return err
	}

	if _, err := parseOptionalHoneytokenUUID(
		req.PolicyID,
		"policy ID",
	); err != nil {
		return err
	}

	if _, err := parseOptionalHoneytokenUUID(
		req.OwnerUserID,
		"owner user ID",
	); err != nil {
		return err
	}

	if _, err := parseHoneytokenExpiration(
		req.ExpiresAt,
	); err != nil {
		return err
	}

	return nil
}

func honeytokenUUIDFromContext(
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
		if err != nil || parsedValue == uuid.Nil {
			return uuid.Nil, false
		}

		return parsedValue, true

	default:
		return uuid.Nil, false
	}
}

func handleCreateHoneytokenError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrHoneytokenCodeExists):
		response.Error(
			c,
			http.StatusConflict,
			"Honeytoken code already exists",
			nil,
		)

	case errors.Is(err, ErrHoneytokenDepartmentNotFound),
		errors.Is(err, ErrHoneytokenPolicyNotFound),
		errors.Is(err, ErrHoneytokenOwnerNotFound),
		errors.Is(err, ErrHoneytokenCreatorNotFound):
		response.NotFound(
			c,
			"One or more honeytoken relations were not found",
			nil,
		)

	case errors.Is(err, ErrEncryptionKeyNotFound):
		response.Error(
			c,
			http.StatusConflict,
			"Active organization encryption key is required",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Honeytoken creation timed out",
			nil,
		)

	case errors.Is(err, ErrHoneytokenServiceUnavailable),
		errors.Is(err, ErrHoneytokenGeneratorUnavailable),
		errors.Is(err, ErrEncryptionKeyServiceUnavailable),
		errors.Is(err, ErrInvalidMasterEncryptionKey),
		errors.Is(err, ErrManagedEncryptionKeyCorrupted):
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Honeytoken security service is unavailable",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to create honeytoken",
			nil,
		)
	}
}

func handleGetHoneytokenError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrHoneytokenNotFound):
		response.NotFound(
			c,
			"Honeytoken not found",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Honeytoken request timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to retrieve honeytoken",
			nil,
		)
	}
}

func handleListHoneytokensError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Honeytoken list request timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to list honeytokens",
			nil,
		)
	}
}

// DeployHoneytoken activates a generated honeytoken at an authorized
// deployment location.
func (h *HoneytokenHandler) DeployHoneytoken(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Honeytoken handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := honeytokenUUIDFromContext(
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

	honeytokenID, err := uuid.Parse(
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil || honeytokenID == uuid.Nil {
		response.BadRequest(
			c,
			"Invalid honeytoken ID",
			nil,
		)
		return
	}

	var request DeployHoneytokenRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid honeytoken deployment payload",
			err.Error(),
		)
		return
	}

	if err := validateDeployHoneytokenRequest(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid honeytoken deployment request",
			err.Error(),
		)
		return
	}

	result, err := h.service.DeployHoneytoken(
		c.Request.Context(),
		organizationID,
		honeytokenID,
		&request,
	)
	if err != nil {
		handleDeployHoneytokenError(
			c,
			err,
		)
		return
	}

	if result == nil {
		internalError := errors.New(
			"honeytoken deployment returned an empty result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to deploy honeytoken",
			nil,
		)
		return
	}

	response.OK(
		c,
		"Honeytoken deployed successfully",
		result,
	)
}

// ValidateHoneytoken validates an observed value and records a trigger
// when it matches an active honeytoken.
func (h *HoneytokenHandler) ValidateHoneytoken(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Honeytoken handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := honeytokenUUIDFromContext(
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

	honeytokenID, err := uuid.Parse(
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil || honeytokenID == uuid.Nil {
		response.BadRequest(
			c,
			"Invalid honeytoken ID",
			nil,
		)
		return
	}

	var request ValidateHoneytokenRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid honeytoken validation payload",
			err.Error(),
		)
		return
	}

	if err := validateHoneytokenValidationRequest(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid honeytoken validation request",
			err.Error(),
		)
		return
	}

	result, err := h.service.ValidateHoneytoken(
		c.Request.Context(),
		organizationID,
		honeytokenID,
		&request,
	)
	if err != nil {
		handleValidateHoneytokenError(
			c,
			err,
		)
		return
	}

	if result == nil {
		internalError := errors.New(
			"honeytoken validation returned an empty result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to validate honeytoken",
			nil,
		)
		return
	}

	response.OK(
		c,
		"Honeytoken validation completed",
		result,
	)
}

func handleDeployHoneytokenError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrHoneytokenNotFound):
		response.NotFound(
			c,
			"Honeytoken not found",
			nil,
		)

	case errors.Is(err, ErrHoneytokenExpired):
		response.Error(
			c,
			http.StatusGone,
			"Honeytoken has expired",
			nil,
		)

	case errors.Is(err, ErrHoneytokenNotDeployable):
		response.Error(
			c,
			http.StatusConflict,
			"Honeytoken cannot be deployed in its current state",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Honeytoken deployment timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to deploy honeytoken",
			nil,
		)
	}
}

func handleValidateHoneytokenError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrHoneytokenNotFound):
		response.NotFound(
			c,
			"Honeytoken not found",
			nil,
		)

	case errors.Is(err, ErrHoneytokenExpired):
		response.Error(
			c,
			http.StatusGone,
			"Honeytoken has expired",
			nil,
		)

	case errors.Is(err, ErrHoneytokenNotActive):
		response.Error(
			c,
			http.StatusConflict,
			"Honeytoken is not active",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Honeytoken validation timed out",
			nil,
		)

	case errors.Is(err, ErrInvalidHoneytokenValueEnvelope),
		errors.Is(err, ErrManagedEncryptionKeyCorrupted),
		errors.Is(err, ErrEncryptionKeyNotFound):
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Honeytoken security verification is unavailable",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to validate honeytoken",
			nil,
		)
	}
}
