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

// EncryptionKeyHandler exposes safe encryption-key management endpoints.
// Raw and encrypted key material is never included in an API response.
type EncryptionKeyHandler struct {
	service *EncryptionKeyService
}

func NewEncryptionKeyHandler(
	service *EncryptionKeyService,
) *EncryptionKeyHandler {
	return &EncryptionKeyHandler{
		service: service,
	}
}

// CreateEncryptionKey creates an organization-specific AES-256 key.
func (h *EncryptionKeyHandler) CreateEncryptionKey(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Encryption key handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := encryptionKeyUUIDFromContext(
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

	var request CreateEncryptionKeyRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	if err := validateCreateEncryptionKeyRequest(
		request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid encryption key request",
			err.Error(),
		)
		return
	}

	createdKey, err := h.service.CreateEncryptionKey(
		c.Request.Context(),
		organizationID,
		request,
	)
	if err != nil {
		handleCreateEncryptionKeyError(
			c,
			err,
		)
		return
	}

	response.Created(
		c,
		"Encryption key created successfully",
		createdKey,
	)
}

// GetActiveEncryptionKey returns safe metadata for the organization's
// currently active encryption key.
func (h *EncryptionKeyHandler) GetActiveEncryptionKey(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Encryption key handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := encryptionKeyUUIDFromContext(
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

	activeKey, err := h.service.GetActiveEncryptionKey(
		c.Request.Context(),
		organizationID,
	)
	if err != nil {
		handleGetActiveEncryptionKeyError(
			c,
			err,
		)
		return
	}

	response.OK(
		c,
		"Active encryption key retrieved successfully",
		activeKey,
	)
}

func (h *EncryptionKeyHandler) isAvailable() bool {
	return h != nil && h.service != nil
}

func encryptionKeyUUIDFromContext(
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

func handleCreateEncryptionKeyError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Encryption key creation timed out",
			nil,
		)

	case errors.Is(err, ErrInvalidMasterEncryptionKey),
		errors.Is(err, ErrEncryptionKeyServiceUnavailable):
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Encryption key service is unavailable",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to create encryption key",
			nil,
		)
	}
}

func handleGetActiveEncryptionKeyError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrEncryptionKeyNotFound):
		response.NotFound(
			c,
			"Active encryption key not found",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Encryption key request timed out",
			nil,
		)

	case errors.Is(err, ErrInvalidMasterEncryptionKey),
		errors.Is(err, ErrEncryptionKeyServiceUnavailable):
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Encryption key service is unavailable",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to retrieve active encryption key",
			nil,
		)
	}
}
