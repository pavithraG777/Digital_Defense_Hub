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

type FileEventHandler struct {
	service *FileEventService
}

func NewFileEventHandler(
	service *FileEventService,
) *FileEventHandler {
	return &FileEventHandler{
		service: service,
	}
}

// CreateFileEvent accepts one authenticated event from a trusted watcher,
// agent or internal security service.
func (h *FileEventHandler) CreateFileEvent(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"File event handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := fileEventUUIDFromContext(
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

	userID, ok := fileEventUUIDFromContext(
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

	var request CreateFileEventRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	applicationUserID := userID

	createdEvent, err := h.service.CreateFileEvent(
		c.Request.Context(),
		organizationID,
		&applicationUserID,
		c.ClientIP(),
		request,
	)
	if err != nil {
		handleCreateFileEventError(c, err)
		return
	}

	response.Created(
		c,
		"File event recorded successfully",
		createdEvent,
	)
}

func (h *FileEventHandler) GetFileEvent(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"File event handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := fileEventUUIDFromContext(
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

	eventID := strings.TrimSpace(c.Param("id"))

	if _, err := uuid.Parse(eventID); err != nil {
		response.BadRequest(
			c,
			"Invalid file event ID",
			err.Error(),
		)
		return
	}

	event, err := h.service.GetFileEvent(
		c.Request.Context(),
		organizationID,
		eventID,
	)
	if err != nil {
		handleGetFileEventError(c, err)
		return
	}

	response.OK(
		c,
		"File event retrieved successfully",
		event,
	)
}

func (h *FileEventHandler) ListFileEvents(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"File event handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := fileEventUUIDFromContext(
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

	var request ListFileEventsRequest

	if err := c.ShouldBindQuery(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid file event filters",
			err.Error(),
		)
		return
	}

	events, err := h.service.ListFileEvents(
		c.Request.Context(),
		organizationID,
		request,
	)
	if err != nil {
		handleListFileEventsError(c, err)
		return
	}

	response.OK(
		c,
		"File events retrieved successfully",
		events,
	)
}

func (h *FileEventHandler) isAvailable() bool {
	return h != nil && h.service != nil
}

func fileEventUUIDFromContext(
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

func handleCreateFileEventError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrInvalidFileEventRequest),
		errors.Is(err, ErrFileEventFutureTimestamp),
		errors.Is(err, ErrFileEventSourceReferenceRequired),
		errors.Is(err, ErrFileEventSourceReferenceMismatch),
		errors.Is(err, ErrInvalidFileEventHash),
		errors.Is(err, ErrInvalidFileEventJSON),
		errors.Is(err, ErrInvalidFileEventIPAddress),
		errors.Is(err, ErrInvalidFileEventMACAddress):
		response.BadRequest(
			c,
			"Invalid file event request",
			err.Error(),
		)

	case errors.Is(err, ErrFileEventDepartmentNotFound),
		errors.Is(err, ErrFileEventRuleNotFound),
		errors.Is(err, ErrFileEventProtectedFileNotFound),
		errors.Is(err, ErrFileEventHoneytokenNotFound),
		errors.Is(err, ErrFileEventCanaryNotFound),
		errors.Is(err, ErrFileEventUserNotFound):
		response.BadRequest(
			c,
			"Referenced event resource is unavailable",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"File event recording timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to record file event",
			nil,
		)
	}
}

func handleGetFileEventError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrFileEventNotFound):
		response.NotFound(
			c,
			"File event not found",
			nil,
		)

	case errors.Is(err, ErrInvalidFileEventRequest):
		response.BadRequest(
			c,
			"Invalid file event request",
			err.Error(),
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"File event request timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to retrieve file event",
			nil,
		)
	}
}

func handleListFileEventsError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrInvalidFileEventRequest):
		response.BadRequest(
			c,
			"Invalid file event filters",
			err.Error(),
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"File event request timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to retrieve file events",
			nil,
		)
	}
}
