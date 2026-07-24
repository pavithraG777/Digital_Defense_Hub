package router

import (
	"context"
	"errors"

	honeytoken "github.com/pavithraG777/cyber-security-platform/backend/internal/HoneyToken"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/notification"
)

// securityNotificationPublisher connects the HoneyToken Threat Engine with the
// Notification Engine without introducing a package import cycle.
type securityNotificationPublisher struct {
	service *notification.SecurityNotificationService
}

func newSecurityNotificationPublisher(
	service *notification.SecurityNotificationService,
) (
	honeytoken.SecurityNotificationPublisher,
	error,
) {
	if service == nil {
		return nil, errors.New(
			"security notification service is required",
		)
	}

	return &securityNotificationPublisher{
		service: service,
	}, nil
}

func (publisher *securityNotificationPublisher) PublishSecurityNotification(
	ctx context.Context,
	event honeytoken.SecurityNotificationEvent,
) error {
	if publisher == nil ||
		publisher.service == nil {
		return errors.New(
			"security notification publisher is unavailable",
		)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	return publisher.service.PublishSecurityAlert(
		ctx,
		notification.SecurityAlertInput{
			OrganizationID: event.OrganizationID,
			DepartmentID:   event.DepartmentID,
			ThreatID:       event.ThreatID,
			IncidentID:     event.IncidentID,

			NotificationType: event.EventType,
			Category:         event.Category,
			Title:            event.Title,
			Message:          event.Message,
			Severity:         event.Severity,

			PriorityLevel: event.PriorityLevel,

			DeduplicationKey: event.DeduplicationKey,

			RequiresAcknowledgement: event.RequiresAcknowledgement,

			Payload: event.Payload,
		},
	)
}
