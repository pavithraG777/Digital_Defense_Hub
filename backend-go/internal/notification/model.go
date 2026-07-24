package notification

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Notification represents one organization security or system notification.
type Notification struct {
	ID                   uuid.UUID
	NotificationSequence int64
	NotificationCode     string

	OrganizationID uuid.UUID
	DepartmentID   *uuid.UUID

	IncidentID *uuid.UUID
	ThreatID   *uuid.UUID

	NotificationType string
	Category         string

	Title    string
	Message  string
	Severity string

	PriorityLevel int

	DeduplicationKey *string
	Payload          json.RawMessage

	RequiresAcknowledgement bool
	AcknowledgedBy          *uuid.UUID
	AcknowledgedAt          *time.Time

	Status string

	CreatedBy   *uuid.UUID
	ScheduledAt *time.Time
	ExpiresAt   *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// Recipient represents one internal or external notification recipient.
type Recipient struct {
	ID uuid.UUID

	NotificationID uuid.UUID
	OrganizationID uuid.UUID

	RecipientType string
	UserID        *uuid.UUID

	RecipientName *string
	EmailAddress  *string
	PhoneNumber   *string

	InAppStatus    string
	ReadAt         *time.Time
	AcknowledgedAt *time.Time
	DismissedAt    *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Delivery represents one notification delivery channel attempt.
type Delivery struct {
	ID uuid.UUID

	NotificationID uuid.UUID
	RecipientID    uuid.UUID
	OrganizationID uuid.UUID

	Channel        string
	DeliveryStatus string

	AttemptCount    int
	MaximumAttempts int

	ProviderName      *string
	ProviderMessageID *string

	LastError        *string
	ProviderResponse json.RawMessage

	ScheduledAt         time.Time
	NextRetryAt         *time.Time
	ProcessingStartedAt *time.Time
	SentAt              *time.Time
	DeliveredAt         *time.Time
	FailedAt            *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}
