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

// RegisterProtectedFile validates the authenticated tenant and user,
// protects the requested file and returns its vault registration details.
func (h *Handler) RegisterProtectedFile(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Protected file handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := protectedFileUUIDFromContext(
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

	ownerUserID, ok := protectedFileUUIDFromContext(
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

	var request RegisterProtectedFileRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	if err := validateRegisterProtectedFileRequest(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid protected file request",
			err.Error(),
		)
		return
	}

	if _, err := parseOptionalDepartmentID(
		request.DepartmentID,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid protected file request",
			err.Error(),
		)
		return
	}

	if !requestIdentityMatches(
		request.OrganizationID,
		organizationID,
	) {
		response.Forbidden(
			c,
			"Organization ID does not match the authenticated organization",
			nil,
		)
		return
	}

	if !requestIdentityMatches(
		request.OwnerUserID,
		ownerUserID,
	) {
		response.Forbidden(
			c,
			"Owner user ID does not match the authenticated user",
			nil,
		)
		return
	}

	// Always use trusted authentication values after verifying the payload.
	request.OrganizationID = organizationID.String()
	request.OwnerUserID = ownerUserID.String()

	registration, err := h.service.RegisterProtectedFile(
		c.Request.Context(),
		&request,
	)
	if err != nil {
		handleProtectedFileRegistrationError(
			c,
			err,
		)
		return
	}

	response.Created(
		c,
		"Protected file registered successfully",
		registration,
	)
}

// GetProtectedFile returns safe protected-file metadata without exposing
// local storage paths, encryption key identifiers or cryptographic hashes.
func (h *Handler) GetProtectedFile(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Protected file handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := protectedFileUUIDFromContext(
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

	protectedFileID, err := uuid.Parse(
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil {
		response.BadRequest(
			c,
			"Invalid protected file ID",
			err.Error(),
		)
		return
	}

	file, err := h.service.GetProtectedFile(
		c.Request.Context(),
		protectedFileID,
	)
	if err != nil {
		handleGetProtectedFileError(
			c,
			err,
		)
		return
	}

	if file == nil {
		internalError := errors.New(
			"protected file service returned an empty result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to retrieve protected file",
			nil,
		)
		return
	}

	// Hide records belonging to another organization.
	if file.OrganizationID != organizationID {
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)
		return
	}

	response.OK(
		c,
		"Protected file retrieved successfully",
		buildGetProtectedFileResponse(file),
	)
}

func (h *Handler) isAvailable() bool {
	return h != nil && h.service != nil
}

func protectedFileUUIDFromContext(
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
		if typedValue == nil || *typedValue == uuid.Nil {
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

func requestIdentityMatches(
	requestValue string,
	authenticatedValue uuid.UUID,
) bool {
	requestID, err := uuid.Parse(
		strings.TrimSpace(requestValue),
	)
	if err != nil {
		return false
	}

	return requestID == authenticatedValue
}

func handleProtectedFileRegistrationError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrSourceFileNotFound):
		response.NotFound(
			c,
			"Source file was not found",
			nil,
		)

	case errors.Is(err, ErrInvalidSourceFile):
		response.BadRequest(
			c,
			"Source path must point to a regular file",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Protected file registration timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to register protected file",
			nil,
		)
	}
}

func handleGetProtectedFileError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrProtectedFileNotFound):
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Protected file request timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to retrieve protected file",
			nil,
		)
	}
}

func buildGetProtectedFileResponse(
	file *ProtectedFile,
) *GetProtectedFileResponse {
	departmentID := ""

	if file.DepartmentID != nil {
		departmentID = file.DepartmentID.String()
	}

	return &GetProtectedFileResponse{
		ID:             file.ID.String(),
		OrganizationID: file.OrganizationID.String(),
		DepartmentID:   departmentID,
		OwnerUserID:    file.OwnerUserID.String(),

		OriginalFileName:  file.OriginalFileName,
		ProtectedFileName: file.ProtectedFileName,

		Category:       file.Category,
		Sensitivity:    file.Sensitivity,
		Classification: file.Classification,

		FileSizeBytes: file.FileSizeBytes,
		MimeType:      file.MimeType,
		Status:        file.Status,

		MonitoringEnabled: file.MonitoringEnabled,
		HoneytokenEnabled: file.HoneytokenEnabled,
		CanaryEnabled:     file.CanaryEnabled,

		CreatedAt: file.CreatedAt.
			UTC().
			Format(time.RFC3339),
	}
}

// RestoreProtectedFile handles an authorized request to decrypt and
// restore an original file from its protected .ddh package.
func (h *Handler) RestoreProtectedFile(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Protected file handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := protectedFileUUIDFromContext(
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

	protectedFileID, err := uuid.Parse(
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil {
		response.BadRequest(
			c,
			"Invalid protected file ID",
			err.Error(),
		)
		return
	}

	var request RestoreProtectedFileRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid restore request payload",
			err.Error(),
		)
		return
	}

	if err := validateRestoreProtectedFileRequest(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid restore request",
			err.Error(),
		)
		return
	}

	result, err := h.service.RestoreProtectedFile(
		c.Request.Context(),
		protectedFileID,
		organizationID,
		&request,
	)
	if err != nil {
		handleRestoreProtectedFileError(
			c,
			err,
		)
		return
	}

	if result == nil {
		internalError := errors.New(
			"protected file restore returned an empty result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to restore protected file",
			nil,
		)
		return
	}

	response.OK(
		c,
		"Protected file restored successfully",
		result,
	)
}

func handleRestoreProtectedFileError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrProtectedFileNotFound):
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)

	case errors.Is(err, ErrProtectedPackageNotFound):
		response.NotFound(
			c,
			"Protected package was not found",
			nil,
		)

	case errors.Is(err, ErrRestoreTargetAlreadyExists):
		response.Error(
			c,
			http.StatusConflict,
			"Restored file already exists",
			nil,
		)

	case errors.Is(err, ErrProtectedFileNotRestorable):
		response.Error(
			c,
			http.StatusConflict,
			"Protected file cannot be restored in its current state",
			nil,
		)

	case errors.Is(err, ErrInvalidProtectedPackage),
		errors.Is(err, ErrProtectedPackageAuthenticationFailed),
		errors.Is(err, ErrDecryptedFileIntegrityCheckFailed):
		response.Error(
			c,
			http.StatusUnprocessableEntity,
			"Protected package failed security verification",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Protected file restoration timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to restore protected file",
			nil,
		)
	}
}
