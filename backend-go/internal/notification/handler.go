package notification

import (
	"context"
	"errors"
	"net/http"
	"strings"

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

func (h *Handler) CreateNotification(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Notification handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := notificationContextUUID(
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

	userID, ok := notificationContextUUID(
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

	var request CreateNotificationRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid notification request",
			err.Error(),
		)
		return
	}

	createdBy := userID

	createdNotification, err :=
		h.service.CreateNotification(
			c.Request.Context(),
			organizationID,
			&createdBy,
			request,
		)
	if err != nil {
		handleNotificationError(c, err)
		return
	}

	response.Created(
		c,
		"Notification created successfully",
		createdNotification,
	)
}

func (h *Handler) GetNotification(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Notification handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := notificationContextUUID(
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

	notificationID, ok :=
		notificationPathUUID(c)
	if !ok {
		return
	}

	notificationRecord, err :=
		h.service.GetNotification(
			c.Request.Context(),
			organizationID,
			notificationID,
		)
	if err != nil {
		handleNotificationError(c, err)
		return
	}

	response.OK(
		c,
		"Notification retrieved successfully",
		notificationRecord,
	)
}

func (h *Handler) ListNotifications(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Notification handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := notificationContextUUID(
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

	var query NotificationListQuery

	if err := c.ShouldBindQuery(&query); err != nil {
		response.BadRequest(
			c,
			"Invalid notification query",
			err.Error(),
		)
		return
	}

	notifications, err :=
		h.service.ListNotifications(
			c.Request.Context(),
			organizationID,
			query,
		)
	if err != nil {
		handleNotificationError(c, err)
		return
	}

	response.OK(
		c,
		"Notifications retrieved successfully",
		notifications,
	)
}

func (h *Handler) ListMyNotifications(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Notification handler is unavailable",
			nil,
		)
		return
	}

	organizationID, userID, ok :=
		notificationUserContext(c)
	if !ok {
		return
	}

	var query UserNotificationListQuery

	if err := c.ShouldBindQuery(&query); err != nil {
		response.BadRequest(
			c,
			"Invalid user notification query",
			err.Error(),
		)
		return
	}

	notifications, err :=
		h.service.ListUserNotifications(
			c.Request.Context(),
			organizationID,
			userID,
			query,
		)
	if err != nil {
		handleNotificationError(c, err)
		return
	}

	response.OK(
		c,
		"User notifications retrieved successfully",
		notifications,
	)
}

func (h *Handler) MarkNotificationRead(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Notification handler is unavailable",
			nil,
		)
		return
	}

	organizationID, userID, ok :=
		notificationUserContext(c)
	if !ok {
		return
	}

	notificationID, ok :=
		notificationPathUUID(c)
	if !ok {
		return
	}

	notificationRecord, err :=
		h.service.MarkNotificationRead(
			c.Request.Context(),
			organizationID,
			userID,
			notificationID,
		)
	if err != nil {
		handleNotificationError(c, err)
		return
	}

	response.OK(
		c,
		"Notification marked as read successfully",
		notificationRecord,
	)
}

func (h *Handler) MarkAllNotificationsRead(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Notification handler is unavailable",
			nil,
		)
		return
	}

	organizationID, userID, ok :=
		notificationUserContext(c)
	if !ok {
		return
	}

	updatedCount, err :=
		h.service.MarkAllNotificationsRead(
			c.Request.Context(),
			organizationID,
			userID,
		)
	if err != nil {
		handleNotificationError(c, err)
		return
	}

	response.OK(
		c,
		"Notifications marked as read successfully",
		gin.H{
			"updated_count": updatedCount,
		},
	)
}

func (h *Handler) AcknowledgeNotification(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Notification handler is unavailable",
			nil,
		)
		return
	}

	organizationID, userID, ok :=
		notificationUserContext(c)
	if !ok {
		return
	}

	notificationID, ok :=
		notificationPathUUID(c)
	if !ok {
		return
	}

	notificationRecord, err :=
		h.service.AcknowledgeNotification(
			c.Request.Context(),
			organizationID,
			userID,
			notificationID,
		)
	if err != nil {
		handleNotificationError(c, err)
		return
	}

	response.OK(
		c,
		"Notification acknowledged successfully",
		notificationRecord,
	)
}

func (h *Handler) DismissNotification(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Notification handler is unavailable",
			nil,
		)
		return
	}

	organizationID, userID, ok :=
		notificationUserContext(c)
	if !ok {
		return
	}

	notificationID, ok :=
		notificationPathUUID(c)
	if !ok {
		return
	}

	notificationRecord, err :=
		h.service.DismissNotification(
			c.Request.Context(),
			organizationID,
			userID,
			notificationID,
		)
	if err != nil {
		handleNotificationError(c, err)
		return
	}

	response.OK(
		c,
		"Notification dismissed successfully",
		notificationRecord,
	)
}

func (h *Handler) CancelNotification(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Notification handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := notificationContextUUID(
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

	notificationID, ok :=
		notificationPathUUID(c)
	if !ok {
		return
	}

	notificationRecord, err :=
		h.service.CancelNotification(
			c.Request.Context(),
			organizationID,
			notificationID,
		)
	if err != nil {
		handleNotificationError(c, err)
		return
	}

	response.OK(
		c,
		"Notification cancelled successfully",
		notificationRecord,
	)
}

func (h *Handler) isAvailable() bool {
	return h != nil &&
		h.service != nil
}

func notificationUserContext(
	c *gin.Context,
) (uuid.UUID, uuid.UUID, bool) {
	organizationID, ok :=
		notificationContextUUID(
			c,
			"organization_id",
		)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return uuid.Nil, uuid.Nil, false
	}

	userID, ok := notificationContextUUID(
		c,
		"user_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return uuid.Nil, uuid.Nil, false
	}

	return organizationID, userID, true
}

func notificationContextUUID(
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

func notificationPathUUID(
	c *gin.Context,
) (string, bool) {
	notificationID := strings.TrimSpace(
		c.Param("id"),
	)

	parsedNotificationID, err :=
		uuid.Parse(notificationID)
	if err != nil ||
		parsedNotificationID == uuid.Nil {
		response.BadRequest(
			c,
			"Invalid notification ID",
			"notification ID must be a valid UUID",
		)
		return "", false
	}

	return parsedNotificationID.String(), true
}

func handleNotificationError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrNotificationNotFound):
		response.NotFound(
			c,
			"Notification not found",
			nil,
		)

	case errors.Is(
		err,
		ErrNotificationRecipientNotFound,
	):
		response.NotFound(
			c,
			"Notification recipient not found",
			nil,
		)

	case errors.Is(
		err,
		ErrNotificationReferenceNotFound,
	):
		response.BadRequest(
			c,
			"Referenced notification resource is unavailable",
			nil,
		)

	case errors.Is(
		err,
		ErrNotificationDuplicate,
	):
		response.Error(
			c,
			http.StatusConflict,
			"Duplicate notification",
			err.Error(),
		)

	case errors.Is(
		err,
		ErrNotificationCodeExists,
	):
		response.Error(
			c,
			http.StatusConflict,
			"Notification code already exists",
			err.Error(),
		)

	case errors.Is(err, context.Canceled),
		errors.Is(
			err,
			context.DeadlineExceeded,
		):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Notification request timed out",
			nil,
		)

	case isNotificationConflictError(err):
		response.Error(
			c,
			http.StatusConflict,
			"Notification operation is not allowed",
			err.Error(),
		)

	case isNotificationClientError(err):
		response.BadRequest(
			c,
			"Invalid notification request",
			err.Error(),
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Notification operation failed",
			nil,
		)
	}
}

func isNotificationConflictError(
	err error,
) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(
		err.Error(),
	)

	conflictMessages := []string{
		"already acknowledged",
		"already dismissed",
		"already cancelled",
		"cannot be cancelled",
		"cannot cancel",
		"invalid status transition",
	}

	for _, conflictMessage := range conflictMessages {
		if strings.Contains(
			message,
			conflictMessage,
		) {
			return true
		}
	}

	return false
}

func isNotificationClientError(
	err error,
) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(
		err.Error(),
	)

	clientErrorMessages := []string{
		" is required",
		" must ",
		"invalid ",
		"unsupported ",
		"does not belong",
		"cannot be empty",
		"must not",
	}

	for _, clientErrorMessage := range clientErrorMessages {
		if strings.Contains(
			message,
			clientErrorMessage,
		) {
			return true
		}
	}

	return false
}
