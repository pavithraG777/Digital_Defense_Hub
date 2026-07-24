package notification

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

func (s *Service) MarkNotificationRead(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	notificationID string,
) (*UserNotificationResponse, error) {
	if err := s.validateUserWorkflowDependencies(
		organizationID,
		userID,
	); err != nil {
		return nil, err
	}

	parsedNotificationID, err :=
		parseNotificationRequiredUUID(
			notificationID,
			"notification ID",
		)
	if err != nil {
		return nil, err
	}

	recipient, err :=
		s.repository.MarkRecipientRead(
			ctx,
			organizationID,
			userID,
			parsedNotificationID,
			time.Now().UTC(),
		)
	if err != nil {
		return nil, err
	}

	return s.buildUserNotificationWorkflowResponse(
		ctx,
		organizationID,
		parsedNotificationID,
		recipient,
	)
}

func (s *Service) MarkAllNotificationsRead(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
) (int64, error) {
	if err := s.validateUserWorkflowDependencies(
		organizationID,
		userID,
	); err != nil {
		return 0, err
	}

	updatedCount, err :=
		s.repository.MarkAllRecipientsRead(
			ctx,
			organizationID,
			userID,
			time.Now().UTC(),
		)
	if err != nil {
		return 0, err
	}

	return updatedCount, nil
}

func (s *Service) AcknowledgeNotification(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	notificationID string,
) (*UserNotificationResponse, error) {
	if err := s.validateUserWorkflowDependencies(
		organizationID,
		userID,
	); err != nil {
		return nil, err
	}

	parsedNotificationID, err :=
		parseNotificationRequiredUUID(
			notificationID,
			"notification ID",
		)
	if err != nil {
		return nil, err
	}

	recipient, err :=
		s.repository.AcknowledgeRecipient(
			ctx,
			organizationID,
			userID,
			parsedNotificationID,
			time.Now().UTC(),
		)
	if err != nil {
		return nil, err
	}

	return s.buildUserNotificationWorkflowResponse(
		ctx,
		organizationID,
		parsedNotificationID,
		recipient,
	)
}

func (s *Service) DismissNotification(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	notificationID string,
) (*UserNotificationResponse, error) {
	if err := s.validateUserWorkflowDependencies(
		organizationID,
		userID,
	); err != nil {
		return nil, err
	}

	parsedNotificationID, err :=
		parseNotificationRequiredUUID(
			notificationID,
			"notification ID",
		)
	if err != nil {
		return nil, err
	}

	recipient, err :=
		s.repository.DismissRecipient(
			ctx,
			organizationID,
			userID,
			parsedNotificationID,
			time.Now().UTC(),
		)
	if err != nil {
		return nil, err
	}

	return s.buildUserNotificationWorkflowResponse(
		ctx,
		organizationID,
		parsedNotificationID,
		recipient,
	)
}

func (s *Service) CancelNotification(
	ctx context.Context,
	organizationID uuid.UUID,
	notificationID string,
) (*NotificationResponse, error) {
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

	parsedNotificationID, err :=
		parseNotificationRequiredUUID(
			notificationID,
			"notification ID",
		)
	if err != nil {
		return nil, err
	}

	notificationRecord, err :=
		s.repository.CancelNotification(
			ctx,
			organizationID,
			parsedNotificationID,
			time.Now().UTC(),
		)
	if err != nil {
		return nil, err
	}

	return s.buildNotificationResponse(
		ctx,
		notificationRecord,
	)
}

func (s *Service) buildUserNotificationWorkflowResponse(
	ctx context.Context,
	organizationID uuid.UUID,
	notificationID uuid.UUID,
	recipient *Recipient,
) (*UserNotificationResponse, error) {
	if recipient == nil {
		return nil, ErrNotificationRecipientNotFound
	}

	notificationRecord, err :=
		s.repository.FindByID(
			ctx,
			organizationID,
			notificationID,
		)
	if err != nil {
		return nil, err
	}

	response := &UserNotificationResponse{
		Notification: convertNotificationResponse(
			notificationRecord,
			nil,
			nil,
		),
		RecipientID:    recipient.ID.String(),
		InAppStatus:    recipient.InAppStatus,
		ReadAt:         recipient.ReadAt,
		AcknowledgedAt: recipient.AcknowledgedAt,
		DismissedAt:    recipient.DismissedAt,
	}

	return response, nil
}

func (s *Service) validateUserWorkflowDependencies(
	organizationID uuid.UUID,
	userID uuid.UUID,
) error {
	if s == nil || s.repository == nil {
		return errors.New(
			"notification service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return errors.New(
			"organization ID is required",
		)
	}

	if userID == uuid.Nil {
		return errors.New(
			"user ID is required",
		)
	}

	return nil
}
