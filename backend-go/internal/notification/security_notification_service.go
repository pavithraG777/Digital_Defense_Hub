package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

var ErrSecurityNotificationRecipientsUnavailable = errors.New(
	"security notification recipients are unavailable",
)

type SecurityAlertInput struct {
	OrganizationID uuid.UUID
	DepartmentID   *uuid.UUID
	ThreatID       *uuid.UUID
	IncidentID     *uuid.UUID

	NotificationType string
	Category         string
	Title            string
	Message          string
	Severity         string
	PriorityLevel    int

	DeduplicationKey        string
	RequiresAcknowledgement bool
	Payload                 json.RawMessage
}

type SecurityNotificationService struct {
	repository          *Repository
	notificationService *Service
	providers           *ProviderRegistry
}

func NewSecurityNotificationService(
	repository *Repository,
	notificationService *Service,
	providers *ProviderRegistry,
) (*SecurityNotificationService, error) {
	if repository == nil {
		return nil, errors.New(
			"notification repository is required",
		)
	}

	if notificationService == nil {
		return nil, errors.New(
			"notification service is required",
		)
	}

	if providers == nil {
		return nil, errors.New(
			"notification provider registry is required",
		)
	}

	return &SecurityNotificationService{
		repository:          repository,
		notificationService: notificationService,
		providers:           providers,
	}, nil
}

func (s *SecurityNotificationService) PublishSecurityAlert(
	ctx context.Context,
	input SecurityAlertInput,
) error {
	if err := validateSecurityAlertInput(
		input,
	); err != nil {
		return err
	}

	recipients, err :=
		s.repository.
			ListSecurityNotificationRecipients(
				ctx,
				input.OrganizationID,
			)
	if err != nil {
		return err
	}

	if len(recipients) == 0 {
		return ErrSecurityNotificationRecipientsUnavailable
	}

	requestRecipients := make(
		[]CreateRecipientRequest,
		0,
		len(recipients),
	)

	for _, recipient := range recipients {
		channels := []string{
			"IN_APP",
		}

		if s.providers.Has(
			"LOCAL_DESKTOP",
		) {
			channels = append(
				channels,
				"LOCAL_DESKTOP",
			)
		}

		emailAddress :=
			copySecurityNotificationString(
				recipient.EmailAddress,
			)

		if emailAddress != nil &&
			s.providers.Has("EMAIL") {
			channels = append(
				channels,
				"EMAIL",
			)
		}

		phoneNumber :=
			copySecurityNotificationString(
				recipient.PhoneNumber,
			)

		if phoneNumber != nil &&
			s.providers.Has("SMS") {
			channels = append(
				channels,
				"SMS",
			)
		}

		userID := recipient.UserID.String()
		recipientName := strings.TrimSpace(
			recipient.RecipientName,
		)

		requestRecipients = append(
			requestRecipients,
			CreateRecipientRequest{
				RecipientType: "USER",
				UserID:        &userID,
				RecipientName: &recipientName,
				EmailAddress:  emailAddress,
				PhoneNumber:   phoneNumber,
				Channels:      channels,
			},
		)
	}

	priorityLevel := input.PriorityLevel
	if priorityLevel <= 0 {
		priorityLevel =
			securityNotificationPriority(
				input.Severity,
			)
	}

	deduplicationKey := strings.TrimSpace(
		input.DeduplicationKey,
	)
	if deduplicationKey == "" {
		deduplicationKey =
			buildSecurityNotificationDeduplicationKey(
				input,
			)
	}

	requiresAcknowledgement :=
		input.RequiresAcknowledgement ||
			securityNotificationRequiresAcknowledgement(
				input.Severity,
			)

	request := CreateNotificationRequest{
		DepartmentID: securityNotificationUUIDString(
			input.DepartmentID,
		),
		IncidentID: securityNotificationUUIDString(
			input.IncidentID,
		),
		ThreatID: securityNotificationUUIDString(
			input.ThreatID,
		),
		NotificationType: strings.ToUpper(
			strings.TrimSpace(
				input.NotificationType,
			),
		),
		Category: strings.ToUpper(
			strings.TrimSpace(input.Category),
		),
		Title: strings.TrimSpace(
			input.Title,
		),
		Message: strings.TrimSpace(
			input.Message,
		),
		Severity: strings.ToUpper(
			strings.TrimSpace(input.Severity),
		),
		PriorityLevel:           &priorityLevel,
		DeduplicationKey:        &deduplicationKey,
		Payload:                 normalizeSecurityNotificationPayload(input.Payload),
		RequiresAcknowledgement: requiresAcknowledgement,
		Recipients:              requestRecipients,
	}

	_, err = s.notificationService.CreateNotification(
		ctx,
		input.OrganizationID,
		nil,
		request,
	)
	if errors.Is(
		err,
		ErrNotificationDuplicate,
	) {
		return nil
	}

	if err != nil {
		return fmt.Errorf(
			"create automatic security notification: %w",
			err,
		)
	}

	return nil
}

func validateSecurityAlertInput(
	input SecurityAlertInput,
) error {
	if input.OrganizationID == uuid.Nil {
		return errors.New(
			"security alert organization ID is required",
		)
	}

	if strings.TrimSpace(
		input.NotificationType,
	) == "" {
		return errors.New(
			"security alert notification type is required",
		)
	}

	if strings.TrimSpace(input.Category) == "" {
		return errors.New(
			"security alert category is required",
		)
	}

	if strings.TrimSpace(input.Title) == "" {
		return errors.New(
			"security alert title is required",
		)
	}

	if strings.TrimSpace(input.Message) == "" {
		return errors.New(
			"security alert message is required",
		)
	}

	if strings.TrimSpace(input.Severity) == "" {
		return errors.New(
			"security alert severity is required",
		)
	}

	return nil
}

func securityNotificationPriority(
	severity string,
) int {
	switch strings.ToUpper(
		strings.TrimSpace(severity),
	) {
	case "CRITICAL":
		return 1

	case "HIGH":
		return 25

	case "MEDIUM":
		return 50

	default:
		return 75
	}
}

func securityNotificationRequiresAcknowledgement(
	severity string,
) bool {
	switch strings.ToUpper(
		strings.TrimSpace(severity),
	) {
	case "CRITICAL", "HIGH":
		return true

	default:
		return false
	}
}

func buildSecurityNotificationDeduplicationKey(
	input SecurityAlertInput,
) string {
	notificationType := strings.ToUpper(
		strings.TrimSpace(
			input.NotificationType,
		),
	)

	if input.IncidentID != nil &&
		*input.IncidentID != uuid.Nil {
		return notificationType +
			":INCIDENT:" +
			input.IncidentID.String()
	}

	if input.ThreatID != nil &&
		*input.ThreatID != uuid.Nil {
		return notificationType +
			":THREAT:" +
			input.ThreatID.String()
	}

	return notificationType +
		":" +
		input.OrganizationID.String() +
		":" +
		strings.ToUpper(
			strings.TrimSpace(input.Title),
		)
}

func securityNotificationUUIDString(
	value *uuid.UUID,
) *string {
	if value == nil ||
		*value == uuid.Nil {
		return nil
	}

	normalizedValue := value.String()

	return &normalizedValue
}

func copySecurityNotificationString(
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

func normalizeSecurityNotificationPayload(
	payload json.RawMessage,
) json.RawMessage {
	if len(payload) == 0 ||
		!json.Valid(payload) {
		return json.RawMessage(`{}`)
	}

	return append(
		json.RawMessage(nil),
		payload...,
	)
}
