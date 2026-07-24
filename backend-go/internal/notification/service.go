package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

var (
	ErrInvalidNotificationRequest = errors.New(
		"invalid notification request",
	)
	ErrNotificationRecipientsRequired = errors.New(
		"at least one notification recipient is required",
	)
	ErrInvalidNotificationRecipient = errors.New(
		"invalid notification recipient",
	)
	ErrInvalidNotificationChannel = errors.New(
		"invalid notification delivery channel",
	)
	ErrInvalidNotificationSchedule = errors.New(
		"invalid notification schedule",
	)
	ErrInvalidNotificationExpiry = errors.New(
		"invalid notification expiry",
	)
	ErrInvalidNotificationPayload = errors.New(
		"invalid notification payload",
	)
)

type Service struct {
	repository *Repository
}

func NewService(
	repository *Repository,
) (*Service, error) {
	if repository == nil {
		return nil, errors.New(
			"notification repository is required",
		)
	}

	return &Service{
		repository: repository,
	}, nil
}

func (s *Service) CreateNotification(
	ctx context.Context,
	organizationID uuid.UUID,
	createdBy *uuid.UUID,
	request CreateNotificationRequest,
) (*NotificationResponse, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if len(request.Recipients) == 0 {
		return nil, ErrNotificationRecipientsRequired
	}

	normalizedCreatedBy, err :=
		normalizeNotificationCreator(createdBy)
	if err != nil {
		return nil, err
	}

	notificationType := strings.ToUpper(
		strings.TrimSpace(
			request.NotificationType,
		),
	)

	category := strings.ToUpper(
		strings.TrimSpace(
			request.Category,
		),
	)

	severity := strings.ToUpper(
		strings.TrimSpace(
			request.Severity,
		),
	)

	title := strings.TrimSpace(
		request.Title,
	)

	message := strings.TrimSpace(
		request.Message,
	)

	if !isServiceNotificationTypeSupported(
		notificationType,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported notification type",
			ErrInvalidNotificationRequest,
		)
	}

	if !isServiceNotificationCategorySupported(
		category,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported notification category",
			ErrInvalidNotificationRequest,
		)
	}

	if !isServiceNotificationSeveritySupported(
		severity,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported notification severity",
			ErrInvalidNotificationRequest,
		)
	}

	if title == "" {
		return nil, fmt.Errorf(
			"%w: title is required",
			ErrInvalidNotificationRequest,
		)
	}

	if len(title) > 255 {
		return nil, fmt.Errorf(
			"%w: title must not exceed 255 characters",
			ErrInvalidNotificationRequest,
		)
	}

	if message == "" {
		return nil, fmt.Errorf(
			"%w: message is required",
			ErrInvalidNotificationRequest,
		)
	}

	departmentID, err :=
		parseNotificationOptionalUUID(
			request.DepartmentID,
			"department ID",
		)
	if err != nil {
		return nil, err
	}

	incidentID, err :=
		parseNotificationOptionalUUID(
			request.IncidentID,
			"incident ID",
		)
	if err != nil {
		return nil, err
	}

	threatID, err :=
		parseNotificationOptionalUUID(
			request.ThreatID,
			"threat ID",
		)
	if err != nil {
		return nil, err
	}

	priorityLevel, err :=
		resolveNotificationPriority(
			severity,
			request.PriorityLevel,
		)
	if err != nil {
		return nil, err
	}

	deduplicationKey, err :=
		normalizeNotificationDeduplicationKey(
			request.DeduplicationKey,
		)
	if err != nil {
		return nil, err
	}

	payload, err := normalizeNotificationPayload(
		request.Payload,
	)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	scheduledAt, err := parseNotificationSchedule(
		request.ScheduledAt,
		now,
	)
	if err != nil {
		return nil, err
	}

	expiresAt, err := parseNotificationExpiry(
		request.ExpiresAt,
		scheduledAt,
	)
	if err != nil {
		return nil, err
	}

	if deduplicationKey != nil {
		existingNotification, findErr :=
			s.repository.FindByDeduplicationKey(
				ctx,
				organizationID,
				*deduplicationKey,
			)

		if findErr == nil {
			return s.buildNotificationResponse(
				ctx,
				existingNotification,
			)
		}

		if !errors.Is(
			findErr,
			ErrNotificationNotFound,
		) {
			return nil, findErr
		}
	}

	notificationID := uuid.New()

	notificationRecord := &Notification{
		ID:                      notificationID,
		NotificationCode:        generateNotificationCode(notificationID, now),
		OrganizationID:          organizationID,
		DepartmentID:            departmentID,
		IncidentID:              incidentID,
		ThreatID:                threatID,
		NotificationType:        notificationType,
		Category:                category,
		Title:                   title,
		Message:                 message,
		Severity:                severity,
		PriorityLevel:           priorityLevel,
		DeduplicationKey:        deduplicationKey,
		Payload:                 payload,
		RequiresAcknowledgement: request.RequiresAcknowledgement,
		Status:                  "CREATED",
		CreatedBy:               normalizedCreatedBy,
		ScheduledAt:             &scheduledAt,
		ExpiresAt:               expiresAt,
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	recipients, deliveries, err :=
		buildNotificationRecipientsAndDeliveries(
			organizationID,
			notificationID,
			request.Recipients,
			scheduledAt,
			now,
		)
	if err != nil {
		return nil, err
	}

	if request.RequiresAcknowledgement &&
		!containsUserNotificationRecipient(
			recipients,
		) {
		return nil, fmt.Errorf(
			"%w: acknowledgement requires at least one user recipient",
			ErrInvalidNotificationRecipient,
		)
	}

	recipientPointers := make(
		[]*Recipient,
		0,
		len(recipients),
	)

	for index := range recipients {
		recipientPointers = append(
			recipientPointers,
			&recipients[index],
		)
	}

	deliveryPointers := make(
		[]*Delivery,
		0,
		len(deliveries),
	)

	for index := range deliveries {
		deliveryPointers = append(
			deliveryPointers,
			&deliveries[index],
		)
	}

	err = s.repository.Create(
		ctx,
		notificationRecord,
		recipientPointers,
		deliveryPointers,
	)
	if errors.Is(err, ErrNotificationDuplicate) &&
		deduplicationKey != nil {
		existingNotification, findErr :=
			s.repository.FindByDeduplicationKey(
				ctx,
				organizationID,
				*deduplicationKey,
			)
		if findErr != nil {
			return nil, findErr
		}

		return s.buildNotificationResponse(
			ctx,
			existingNotification,
		)
	}

	if err != nil {
		return nil, err
	}

	return s.buildNotificationResponse(
		ctx,
		notificationRecord,
	)
}

func (s *Service) GetNotification(
	ctx context.Context,
	organizationID uuid.UUID,
	notificationID string,
) (*NotificationResponse, error) {
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
		s.repository.FindByID(
			ctx,
			organizationID,
			parsedNotificationID,
		)
	if err != nil {
		return nil, err
	}

	return s.buildNotificationResponse(
		ctx,
		notificationRecord,
	)
}

func (s *Service) buildNotificationResponse(
	ctx context.Context,
	notificationRecord *Notification,
) (*NotificationResponse, error) {
	if notificationRecord == nil {
		return nil, ErrNotificationNotFound
	}

	recipients, err := s.repository.ListRecipients(
		ctx,
		notificationRecord.OrganizationID,
		notificationRecord.ID,
	)
	if err != nil {
		return nil, err
	}

	deliveries, err := s.repository.ListDeliveries(
		ctx,
		notificationRecord.OrganizationID,
		notificationRecord.ID,
	)
	if err != nil {
		return nil, err
	}

	response := convertNotificationResponse(
		notificationRecord,
		recipients,
		deliveries,
	)

	return &response, nil
}

func buildNotificationRecipientsAndDeliveries(
	organizationID uuid.UUID,
	notificationID uuid.UUID,
	requests []CreateRecipientRequest,
	scheduledAt time.Time,
	createdAt time.Time,
) ([]Recipient, []Delivery, error) {
	recipients := make(
		[]Recipient,
		0,
		len(requests),
	)

	deliveries := make(
		[]Delivery,
		0,
		len(requests),
	)

	recipientKeys := make(
		map[string]struct{},
	)

	for index := range requests {
		request := requests[index]

		recipientType := strings.ToUpper(
			strings.TrimSpace(
				request.RecipientType,
			),
		)

		if recipientType != "USER" &&
			recipientType != "EXTERNAL" {
			return nil, nil, fmt.Errorf(
				"%w: unsupported recipient type",
				ErrInvalidNotificationRecipient,
			)
		}

		userID, err := parseNotificationOptionalUUID(
			request.UserID,
			"recipient user ID",
		)
		if err != nil {
			return nil, nil, err
		}

		recipientName :=
			normalizeNotificationOptionalString(
				request.RecipientName,
			)

		emailAddress, err :=
			normalizeNotificationEmail(
				request.EmailAddress,
			)
		if err != nil {
			return nil, nil, err
		}

		phoneNumber, err :=
			normalizeNotificationPhone(
				request.PhoneNumber,
			)
		if err != nil {
			return nil, nil, err
		}

		if recipientType == "USER" &&
			userID == nil {
			return nil, nil, fmt.Errorf(
				"%w: user recipient requires user ID",
				ErrInvalidNotificationRecipient,
			)
		}

		if recipientType == "EXTERNAL" &&
			userID != nil {
			return nil, nil, fmt.Errorf(
				"%w: external recipient cannot contain user ID",
				ErrInvalidNotificationRecipient,
			)
		}

		if recipientType == "EXTERNAL" &&
			emailAddress == nil &&
			phoneNumber == nil {
			return nil, nil, fmt.Errorf(
				"%w: external recipient requires email or phone number",
				ErrInvalidNotificationRecipient,
			)
		}

		channels, err := normalizeNotificationChannels(
			request.Channels,
			recipientType,
			emailAddress,
			phoneNumber,
		)
		if err != nil {
			return nil, nil, err
		}

		recipientKey := buildNotificationRecipientKey(
			recipientType,
			userID,
			emailAddress,
			phoneNumber,
		)

		if _, exists := recipientKeys[recipientKey]; exists {
			return nil, nil, fmt.Errorf(
				"%w: duplicate recipient",
				ErrInvalidNotificationRecipient,
			)
		}

		recipientKeys[recipientKey] = struct{}{}

		recipientID := uuid.New()

		recipient := Recipient{
			ID:             recipientID,
			NotificationID: notificationID,
			OrganizationID: organizationID,
			RecipientType:  recipientType,
			UserID:         userID,
			RecipientName:  recipientName,
			EmailAddress:   emailAddress,
			PhoneNumber:    phoneNumber,
			InAppStatus:    "UNREAD",
			CreatedAt:      createdAt,
			UpdatedAt:      createdAt,
		}

		recipients = append(
			recipients,
			recipient,
		)

		for _, channel := range channels {
			delivery := Delivery{
				ID:               uuid.New(),
				NotificationID:   notificationID,
				RecipientID:      recipientID,
				OrganizationID:   organizationID,
				Channel:          channel,
				DeliveryStatus:   "QUEUED",
				AttemptCount:     0,
				MaximumAttempts:  5,
				ProviderResponse: json.RawMessage(`{}`),
				ScheduledAt:      scheduledAt,
				CreatedAt:        createdAt,
				UpdatedAt:        createdAt,
			}

			deliveries = append(
				deliveries,
				delivery,
			)
		}
	}

	if len(deliveries) == 0 {
		return nil, nil, fmt.Errorf(
			"%w: at least one delivery channel is required",
			ErrInvalidNotificationChannel,
		)
	}

	return recipients, deliveries, nil
}

func convertNotificationResponse(
	notificationRecord *Notification,
	recipients []Recipient,
	deliveries []Delivery,
) NotificationResponse {
	recipientResponses := make(
		[]NotificationRecipientResponse,
		0,
		len(recipients),
	)

	for index := range recipients {
		recipient := recipients[index]

		recipientResponses = append(
			recipientResponses,
			NotificationRecipientResponse{
				ID:             recipient.ID.String(),
				RecipientType:  recipient.RecipientType,
				UserID:         notificationUUIDPointerToString(recipient.UserID),
				RecipientName:  recipient.RecipientName,
				EmailAddress:   recipient.EmailAddress,
				PhoneNumber:    recipient.PhoneNumber,
				InAppStatus:    recipient.InAppStatus,
				ReadAt:         recipient.ReadAt,
				AcknowledgedAt: recipient.AcknowledgedAt,
				DismissedAt:    recipient.DismissedAt,
				CreatedAt:      recipient.CreatedAt,
				UpdatedAt:      recipient.UpdatedAt,
			},
		)
	}

	deliveryResponses := make(
		[]NotificationDeliveryResponse,
		0,
		len(deliveries),
	)

	for index := range deliveries {
		delivery := deliveries[index]

		deliveryResponses = append(
			deliveryResponses,
			NotificationDeliveryResponse{
				ID:                  delivery.ID.String(),
				RecipientID:         delivery.RecipientID.String(),
				Channel:             delivery.Channel,
				DeliveryStatus:      delivery.DeliveryStatus,
				AttemptCount:        delivery.AttemptCount,
				MaximumAttempts:     delivery.MaximumAttempts,
				ProviderName:        delivery.ProviderName,
				ProviderMessageID:   delivery.ProviderMessageID,
				LastError:           delivery.LastError,
				ScheduledAt:         delivery.ScheduledAt,
				NextRetryAt:         delivery.NextRetryAt,
				ProcessingStartedAt: delivery.ProcessingStartedAt,
				SentAt:              delivery.SentAt,
				DeliveredAt:         delivery.DeliveredAt,
				FailedAt:            delivery.FailedAt,
				CreatedAt:           delivery.CreatedAt,
				UpdatedAt:           delivery.UpdatedAt,
			},
		)
	}

	return NotificationResponse{
		ID:                      notificationRecord.ID.String(),
		NotificationSequence:    notificationRecord.NotificationSequence,
		NotificationCode:        notificationRecord.NotificationCode,
		OrganizationID:          notificationRecord.OrganizationID.String(),
		DepartmentID:            notificationUUIDPointerToString(notificationRecord.DepartmentID),
		IncidentID:              notificationUUIDPointerToString(notificationRecord.IncidentID),
		ThreatID:                notificationUUIDPointerToString(notificationRecord.ThreatID),
		NotificationType:        notificationRecord.NotificationType,
		Category:                notificationRecord.Category,
		Title:                   notificationRecord.Title,
		Message:                 notificationRecord.Message,
		Severity:                notificationRecord.Severity,
		PriorityLevel:           notificationRecord.PriorityLevel,
		Payload:                 notificationRecord.Payload,
		RequiresAcknowledgement: notificationRecord.RequiresAcknowledgement,
		AcknowledgedBy:          notificationUUIDPointerToString(notificationRecord.AcknowledgedBy),
		AcknowledgedAt:          notificationRecord.AcknowledgedAt,
		Status:                  notificationRecord.Status,
		CreatedBy:               notificationUUIDPointerToString(notificationRecord.CreatedBy),
		ScheduledAt:             notificationRecord.ScheduledAt,
		ExpiresAt:               notificationRecord.ExpiresAt,
		CreatedAt:               notificationRecord.CreatedAt,
		UpdatedAt:               notificationRecord.UpdatedAt,
		Recipients:              recipientResponses,
		Deliveries:              deliveryResponses,
	}
}

func generateNotificationCode(
	notificationID uuid.UUID,
	createdAt time.Time,
) string {
	identifier := strings.ReplaceAll(
		notificationID.String(),
		"-",
		"",
	)

	if len(identifier) > 8 {
		identifier = identifier[:8]
	}

	return fmt.Sprintf(
		"DDH-NTF-%s-%s",
		createdAt.UTC().Format("20060102"),
		strings.ToUpper(identifier),
	)
}

func normalizeNotificationCreator(
	createdBy *uuid.UUID,
) (*uuid.UUID, error) {
	if createdBy == nil {
		return nil, nil
	}

	if *createdBy == uuid.Nil {
		return nil, errors.New(
			"created by user ID is invalid",
		)
	}

	normalizedID := *createdBy

	return &normalizedID, nil
}

func parseNotificationRequiredUUID(
	value string,
	fieldName string,
) (uuid.UUID, error) {
	parsedValue, err := uuid.Parse(
		strings.TrimSpace(value),
	)
	if err != nil ||
		parsedValue == uuid.Nil {
		return uuid.Nil, fmt.Errorf(
			"%w: %s must be a valid UUID",
			ErrInvalidNotificationRequest,
			fieldName,
		)
	}

	return parsedValue, nil
}

func parseNotificationOptionalUUID(
	value *string,
	fieldName string,
) (*uuid.UUID, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return nil, nil
	}

	parsedValue, err := uuid.Parse(
		strings.TrimSpace(*value),
	)
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

func parseNotificationSchedule(
	value *string,
	now time.Time,
) (time.Time, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return now.UTC(), nil
	}

	scheduledAt, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(*value),
	)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"%w: scheduled_at must use RFC3339 format",
			ErrInvalidNotificationSchedule,
		)
	}

	scheduledAt = scheduledAt.UTC()

	if scheduledAt.Before(
		now.UTC().Add(-5 * time.Minute),
	) {
		return time.Time{}, fmt.Errorf(
			"%w: scheduled_at is too far in the past",
			ErrInvalidNotificationSchedule,
		)
	}

	if scheduledAt.Before(now.UTC()) {
		scheduledAt = now.UTC()
	}

	return scheduledAt, nil
}

func parseNotificationExpiry(
	value *string,
	scheduledAt time.Time,
) (*time.Time, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return nil, nil
	}

	expiresAt, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(*value),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: expires_at must use RFC3339 format",
			ErrInvalidNotificationExpiry,
		)
	}

	expiresAt = expiresAt.UTC()

	if !expiresAt.After(scheduledAt) {
		return nil, fmt.Errorf(
			"%w: expires_at must be after scheduled_at",
			ErrInvalidNotificationExpiry,
		)
	}

	return &expiresAt, nil
}

func resolveNotificationPriority(
	severity string,
	requestedPriority *int,
) (int, error) {
	if requestedPriority != nil {
		if *requestedPriority < 1 ||
			*requestedPriority > 100 {
			return 0, fmt.Errorf(
				"%w: priority level must be between 1 and 100",
				ErrInvalidNotificationRequest,
			)
		}

		return *requestedPriority, nil
	}

	switch severity {
	case "LOW":
		return 25, nil

	case "MEDIUM":
		return 50, nil

	case "HIGH":
		return 75, nil

	case "CRITICAL":
		return 100, nil

	default:
		return 50, nil
	}
}

func normalizeNotificationDeduplicationKey(
	value *string,
) (*string, error) {
	normalizedValue :=
		normalizeNotificationOptionalString(value)

	if normalizedValue == nil {
		return nil, nil
	}

	if len(*normalizedValue) > 255 {
		return nil, fmt.Errorf(
			"%w: deduplication key must not exceed 255 characters",
			ErrInvalidNotificationRequest,
		)
	}

	return normalizedValue, nil
}

func normalizeNotificationPayload(
	value json.RawMessage,
) (json.RawMessage, error) {
	trimmedValue := bytes.TrimSpace(value)

	if len(trimmedValue) == 0 {
		return json.RawMessage(`{}`), nil
	}

	if !json.Valid(trimmedValue) ||
		trimmedValue[0] != '{' {
		return nil, fmt.Errorf(
			"%w: payload must be a JSON object",
			ErrInvalidNotificationPayload,
		)
	}

	copiedValue := append(
		json.RawMessage(nil),
		trimmedValue...,
	)

	return copiedValue, nil
}

func normalizeNotificationOptionalString(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	normalizedValue := strings.TrimSpace(
		*value,
	)
	if normalizedValue == "" {
		return nil
	}

	return &normalizedValue
}

func normalizeNotificationEmail(
	value *string,
) (*string, error) {
	normalizedValue :=
		normalizeNotificationOptionalString(value)

	if normalizedValue == nil {
		return nil, nil
	}

	address, err := mail.ParseAddress(
		*normalizedValue,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: invalid recipient email address",
			ErrInvalidNotificationRecipient,
		)
	}

	emailAddress := strings.ToLower(
		strings.TrimSpace(
			address.Address,
		),
	)

	return &emailAddress, nil
}

func normalizeNotificationPhone(
	value *string,
) (*string, error) {
	normalizedValue :=
		normalizeNotificationOptionalString(value)

	if normalizedValue == nil {
		return nil, nil
	}

	phoneNumber := strings.ReplaceAll(
		*normalizedValue,
		" ",
		"",
	)

	phoneNumber = strings.ReplaceAll(
		phoneNumber,
		"-",
		"",
	)

	digitCount := 0

	for index, character := range phoneNumber {
		if character == '+' && index == 0 {
			continue
		}

		if !unicode.IsDigit(character) {
			return nil, fmt.Errorf(
				"%w: invalid recipient phone number",
				ErrInvalidNotificationRecipient,
			)
		}

		digitCount++
	}

	if digitCount < 7 ||
		digitCount > 15 {
		return nil, fmt.Errorf(
			"%w: recipient phone number must contain 7 to 15 digits",
			ErrInvalidNotificationRecipient,
		)
	}

	return &phoneNumber, nil
}

func normalizeNotificationChannels(
	values []string,
	recipientType string,
	emailAddress *string,
	phoneNumber *string,
) ([]string, error) {
	if len(values) == 0 {
		if recipientType == "USER" {
			return []string{
				"IN_APP",
			}, nil
		}

		if emailAddress != nil {
			return []string{
				"EMAIL",
			}, nil
		}

		if phoneNumber != nil {
			return []string{
				"SMS",
			}, nil
		}
	}

	channels := make(
		[]string,
		0,
		len(values),
	)

	existingChannels := make(
		map[string]struct{},
	)

	for _, value := range values {
		channel := strings.ToUpper(
			strings.TrimSpace(value),
		)

		if !isServiceNotificationChannelSupported(
			channel,
		) {
			return nil, fmt.Errorf(
				"%w: unsupported channel %s",
				ErrInvalidNotificationChannel,
				channel,
			)
		}

		if channel == "IN_APP" &&
			recipientType != "USER" {
			return nil, fmt.Errorf(
				"%w: IN_APP requires a user recipient",
				ErrInvalidNotificationChannel,
			)
		}

		if channel == "LOCAL_DESKTOP" &&
			recipientType != "USER" {
			return nil, fmt.Errorf(
				"%w: LOCAL_DESKTOP requires a user recipient",
				ErrInvalidNotificationChannel,
			)
		}

		if channel == "EMAIL" &&
			emailAddress == nil {
			return nil, fmt.Errorf(
				"%w: EMAIL requires recipient email address",
				ErrInvalidNotificationChannel,
			)
		}

		if channel == "SMS" &&
			phoneNumber == nil {
			return nil, fmt.Errorf(
				"%w: SMS requires recipient phone number",
				ErrInvalidNotificationChannel,
			)
		}

		if _, exists :=
			existingChannels[channel]; exists {
			continue
		}

		existingChannels[channel] = struct{}{}

		channels = append(
			channels,
			channel,
		)
	}

	if len(channels) == 0 {
		return nil, ErrInvalidNotificationChannel
	}

	return channels, nil
}

func buildNotificationRecipientKey(
	recipientType string,
	userID *uuid.UUID,
	emailAddress *string,
	phoneNumber *string,
) string {
	components := []string{
		recipientType,
	}

	if userID != nil {
		components = append(
			components,
			userID.String(),
		)
	}

	if emailAddress != nil {
		components = append(
			components,
			strings.ToLower(*emailAddress),
		)
	}

	if phoneNumber != nil {
		components = append(
			components,
			*phoneNumber,
		)
	}

	return strings.Join(
		components,
		"|",
	)
}

func containsUserNotificationRecipient(
	recipients []Recipient,
) bool {
	for index := range recipients {
		if recipients[index].RecipientType == "USER" &&
			recipients[index].UserID != nil {
			return true
		}
	}

	return false
}

func notificationUUIDPointerToString(
	value *uuid.UUID,
) *string {
	if value == nil {
		return nil
	}

	normalizedValue := value.String()

	return &normalizedValue
}

func isServiceNotificationTypeSupported(
	value string,
) bool {
	switch value {
	case "THREAT_DETECTED",
		"INCIDENT_CREATED",
		"INCIDENT_ASSIGNED",
		"INCIDENT_STATUS_CHANGED",
		"EVIDENCE_MISMATCH",
		"SYSTEM_ALERT",
		"CUSTOM":
		return true

	default:
		return false
	}
}

func isServiceNotificationCategorySupported(
	value string,
) bool {
	switch value {
	case "SECURITY",
		"INCIDENT",
		"SYSTEM",
		"COMPLIANCE":
		return true

	default:
		return false
	}
}

func isServiceNotificationSeveritySupported(
	value string,
) bool {
	switch value {
	case "LOW",
		"MEDIUM",
		"HIGH",
		"CRITICAL":
		return true

	default:
		return false
	}
}

func isServiceNotificationChannelSupported(
	value string,
) bool {
	switch value {
	case "IN_APP",
		"LOCAL_DESKTOP",
		"EMAIL",
		"SMS",
		"WEBHOOK":
		return true

	default:
		return false
	}
}

func notificationPageCount(
	total int64,
	pageSize int,
) int {
	if total <= 0 ||
		pageSize <= 0 {
		return 0
	}

	return int(
		(total + int64(pageSize) - 1) /
			int64(pageSize),
	)
}

func notificationPageOffset(
	page int,
	pageSize int,
) int {
	if page <= 1 {
		return 0
	}

	return (page - 1) * pageSize
}

func notificationStringPointer(
	value string,
) *string {
	return &value
}

func notificationIntPointer(
	value int,
) *int {
	return &value
}

func notificationIntToString(
	value int,
) string {
	return strconv.Itoa(value)
}
