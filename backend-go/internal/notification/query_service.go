package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (s *Service) ListNotifications(
	ctx context.Context,
	organizationID uuid.UUID,
	request NotificationListQuery,
) (*NotificationListResponse, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"notification service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	departmentID, err :=
		parseNotificationQueryOptionalUUID(
			request.DepartmentID,
			"department ID",
		)
	if err != nil {
		return nil, err
	}

	incidentID, err :=
		parseNotificationQueryOptionalUUID(
			request.IncidentID,
			"incident ID",
		)
	if err != nil {
		return nil, err
	}

	threatID, err :=
		parseNotificationQueryOptionalUUID(
			request.ThreatID,
			"threat ID",
		)
	if err != nil {
		return nil, err
	}

	notificationType := strings.ToUpper(
		strings.TrimSpace(
			request.NotificationType,
		),
	)

	severity := strings.ToUpper(
		strings.TrimSpace(
			request.Severity,
		),
	)

	status := strings.ToUpper(
		strings.TrimSpace(
			request.Status,
		),
	)

	if notificationType != "" &&
		!isServiceNotificationTypeSupported(
			notificationType,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported notification type",
			ErrInvalidNotificationRequest,
		)
	}

	if severity != "" &&
		!isServiceNotificationSeveritySupported(
			severity,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported notification severity",
			ErrInvalidNotificationRequest,
		)
	}

	if status != "" &&
		!isNotificationQueryStatusSupported(
			status,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported notification status",
			ErrInvalidNotificationRequest,
		)
	}

	from, err := parseNotificationQueryTime(
		request.From,
		"from",
	)
	if err != nil {
		return nil, err
	}

	to, err := parseNotificationQueryTime(
		request.To,
		"to",
	)
	if err != nil {
		return nil, err
	}

	if from != nil &&
		to != nil &&
		to.Before(*from) {
		return nil, fmt.Errorf(
			"%w: to must not be before from",
			ErrInvalidNotificationRequest,
		)
	}

	page, pageSize :=
		normalizeNotificationListPagination(
			request.Page,
			request.PageSize,
		)

	records, total, err := s.repository.List(
		ctx,
		NotificationFilter{
			OrganizationID:   organizationID,
			DepartmentID:     departmentID,
			IncidentID:       incidentID,
			ThreatID:         threatID,
			NotificationType: notificationType,
			Severity:         severity,
			Status:           status,
			Search: strings.TrimSpace(
				request.Search,
			),
			From:   from,
			To:     to,
			Limit:  pageSize,
			Offset: notificationPageOffset(page, pageSize),
		},
	)
	if err != nil {
		return nil, err
	}

	notifications := make(
		[]NotificationResponse,
		0,
		len(records),
	)

	for index := range records {
		notifications = append(
			notifications,
			convertNotificationResponse(
				&records[index],
				nil,
				nil,
			),
		)
	}

	return &NotificationListResponse{
		Notifications: notifications,
		Total:         total,
		Page:          page,
		PageSize:      pageSize,
		TotalPages: notificationPageCount(
			total,
			pageSize,
		),
	}, nil
}

func (s *Service) ListUserNotifications(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	request UserNotificationListQuery,
) (*UserNotificationListResponse, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"notification service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if userID == uuid.Nil {
		return nil, errors.New(
			"user ID is required",
		)
	}

	inAppStatus := strings.ToUpper(
		strings.TrimSpace(
			request.InAppStatus,
		),
	)

	severity := strings.ToUpper(
		strings.TrimSpace(
			request.Severity,
		),
	)

	if inAppStatus != "" &&
		!isNotificationInAppStatusSupported(
			inAppStatus,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported in-app status",
			ErrInvalidNotificationRequest,
		)
	}

	if severity != "" &&
		!isServiceNotificationSeveritySupported(
			severity,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported notification severity",
			ErrInvalidNotificationRequest,
		)
	}

	page, pageSize :=
		normalizeNotificationListPagination(
			request.Page,
			request.PageSize,
		)

	records, total, unreadCount, err :=
		s.repository.ListForUser(
			ctx,
			UserNotificationFilter{
				OrganizationID: organizationID,
				UserID:         userID,
				Severity:       severity,
				InAppStatus:    inAppStatus,
				Limit:          pageSize,
				Offset: notificationPageOffset(
					page,
					pageSize,
				),
			},
		)
	if err != nil {
		return nil, err
	}

	notifications := make(
		[]UserNotificationResponse,
		0,
		len(records),
	)

	for index := range records {
		record := records[index]

		notifications = append(
			notifications,
			UserNotificationResponse{
				Notification: convertNotificationResponse(
					&record.Notification,
					nil,
					nil,
				),
				RecipientID:    record.RecipientID.String(),
				InAppStatus:    record.InAppStatus,
				ReadAt:         record.ReadAt,
				AcknowledgedAt: record.AcknowledgedAt,
				DismissedAt:    record.DismissedAt,
			},
		)
	}

	return &UserNotificationListResponse{
		Notifications: notifications,
		UnreadCount:   unreadCount,
		Total:         total,
		Page:          page,
		PageSize:      pageSize,
		TotalPages: notificationPageCount(
			total,
			pageSize,
		),
	}, nil
}

func parseNotificationQueryOptionalUUID(
	value string,
	fieldName string,
) (*uuid.UUID, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		return nil, nil
	}

	parsedValue, err := uuid.Parse(value)
	if err != nil ||
		parsedValue == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: %s must be a valid UUID",
			ErrInvalidNotificationRequest,
			fieldName,
		)
	}

	return &parsedValue, nil
}

func parseNotificationQueryTime(
	value string,
	fieldName string,
) (*time.Time, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		return nil, nil
	}

	parsedValue, err := time.Parse(
		time.RFC3339,
		value,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %s must use RFC3339 format",
			ErrInvalidNotificationRequest,
			fieldName,
		)
	}

	parsedValue = parsedValue.UTC()

	return &parsedValue, nil
}

func normalizeNotificationListPagination(
	page int,
	pageSize int,
) (int, int) {
	if page <= 0 {
		page = 1
	}

	if pageSize <= 0 {
		pageSize = 20
	}

	if pageSize > 100 {
		pageSize = 100
	}

	return page, pageSize
}

func isNotificationQueryStatusSupported(
	value string,
) bool {
	switch value {
	case "CREATED",
		"QUEUED",
		"PARTIALLY_SENT",
		"SENT",
		"FAILED",
		"CANCELLED",
		"EXPIRED":
		return true

	default:
		return false
	}
}

func isNotificationInAppStatusSupported(
	value string,
) bool {
	switch value {
	case "UNREAD",
		"READ",
		"ACKNOWLEDGED",
		"DISMISSED":
		return true

	default:
		return false
	}
}
