package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultLocalDesktopProviderName = "DDH_LOCAL_DESKTOP"
	defaultLocalDesktopOutboxPath   = "./storage/notification-outbox/local-desktop"
)

type LocalDesktopProviderConfig struct {
	ProviderName string
	OutboxPath   string

	DirectoryPermissions os.FileMode
	FilePermissions      os.FileMode
}

type LocalDesktopProvider struct {
	config LocalDesktopProviderConfig
}

type localDesktopNotificationEnvelope struct {
	SchemaVersion int `json:"schema_version"`

	NotificationID   string  `json:"notification_id"`
	NotificationCode string  `json:"notification_code"`
	OrganizationID   string  `json:"organization_id"`
	DepartmentID     *string `json:"department_id,omitempty"`
	IncidentID       *string `json:"incident_id,omitempty"`
	ThreatID         *string `json:"threat_id,omitempty"`

	DeliveryID  string  `json:"delivery_id"`
	RecipientID string  `json:"recipient_id"`
	UserID      *string `json:"user_id,omitempty"`

	NotificationType string `json:"notification_type"`
	Category         string `json:"category"`
	Title            string `json:"title"`
	Message          string `json:"message"`
	Severity         string `json:"severity"`
	PriorityLevel    int    `json:"priority_level"`
	// PlaySound is a client-side instruction. The backend never plays audio on
	// the server; desktop/web clients may emit a short audible alert for urgent
	// notifications after respecting their local accessibility preferences.
	PlaySound bool `json:"play_sound"`

	RequiresAcknowledgement bool            `json:"requires_acknowledgement"`
	Payload                 json.RawMessage `json:"payload"`

	ScheduledAt *time.Time `json:"scheduled_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	QueuedAt    time.Time  `json:"queued_at"`
}

func NewLocalDesktopProvider(
	config LocalDesktopProviderConfig,
) (*LocalDesktopProvider, error) {
	config.ProviderName = strings.TrimSpace(
		config.ProviderName,
	)
	config.OutboxPath = strings.TrimSpace(
		config.OutboxPath,
	)

	if config.ProviderName == "" {
		config.ProviderName =
			defaultLocalDesktopProviderName
	}

	if config.OutboxPath == "" {
		config.OutboxPath =
			defaultLocalDesktopOutboxPath
	}

	if config.DirectoryPermissions == 0 {
		config.DirectoryPermissions = 0750
	}

	if config.FilePermissions == 0 {
		config.FilePermissions = 0600
	}

	absoluteOutboxPath, err := filepath.Abs(
		filepath.Clean(config.OutboxPath),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve local desktop outbox path: %w",
			err,
		)
	}

	if filepath.Clean(absoluteOutboxPath) ==
		filepath.VolumeName(absoluteOutboxPath)+
			string(os.PathSeparator) {
		return nil, errors.New(
			"local desktop outbox path cannot be a filesystem root",
		)
	}

	config.OutboxPath = absoluteOutboxPath

	return &LocalDesktopProvider{
		config: config,
	}, nil
}

func (p *LocalDesktopProvider) Name() string {
	return p.config.ProviderName
}

func (p *LocalDesktopProvider) Channel() string {
	return "LOCAL_DESKTOP"
}

func (p *LocalDesktopProvider) Send(
	ctx context.Context,
	message DeliveryMessage,
) (*ProviderResult, error) {
	if err := ValidateDeliveryMessage(message); err != nil {
		return nil, fmt.Errorf(
			"validate local desktop delivery message: %w",
			err,
		)
	}

	if message.Delivery.Channel != p.Channel() {
		return nil, fmt.Errorf(
			"local desktop provider cannot process %s channel",
			message.Delivery.Channel,
		)
	}

	if message.Recipient.UserID == nil ||
		*message.Recipient.UserID == uuid.Nil {
		return nil, errors.New(
			"local desktop notification requires a user recipient",
		)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	queuedAt := time.Now().UTC()

	envelope := localDesktopNotificationEnvelope{
		SchemaVersion:           1,
		NotificationID:          message.Notification.ID.String(),
		NotificationCode:        message.Notification.NotificationCode,
		OrganizationID:          message.Notification.OrganizationID.String(),
		DepartmentID:            localDesktopOptionalUUID(message.Notification.DepartmentID),
		IncidentID:              localDesktopOptionalUUID(message.Notification.IncidentID),
		ThreatID:                localDesktopOptionalUUID(message.Notification.ThreatID),
		DeliveryID:              message.Delivery.ID.String(),
		RecipientID:             message.Recipient.ID.String(),
		UserID:                  localDesktopOptionalUUID(message.Recipient.UserID),
		NotificationType:        message.Notification.NotificationType,
		Category:                message.Notification.Category,
		Title:                   message.Notification.Title,
		Message:                 message.Notification.Message,
		Severity:                message.Notification.Severity,
		PriorityLevel:           message.Notification.PriorityLevel,
		PlaySound:               localDesktopShouldPlaySound(message.Notification.Severity, message.Notification.PriorityLevel),
		RequiresAcknowledgement: message.Notification.RequiresAcknowledgement,
		Payload:                 normalizeLocalDesktopPayload(message.Notification.Payload),
		ScheduledAt:             message.Notification.ScheduledAt,
		ExpiresAt:               message.Notification.ExpiresAt,
		QueuedAt:                queuedAt,
	}

	encodedEnvelope, err := json.MarshalIndent(
		envelope,
		"",
		"  ",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode local desktop notification: %w",
			err,
		)
	}

	userDirectory := filepath.Join(
		p.config.OutboxPath,
		message.Notification.OrganizationID.String(),
		message.Recipient.UserID.String(),
	)

	destinationPath := filepath.Join(
		userDirectory,
		message.Delivery.ID.String()+".json",
	)

	created, err := p.writeOutboxFile(
		ctx,
		userDirectory,
		destinationPath,
		encodedEnvelope,
	)
	if err != nil {
		return nil, err
	}

	queueStatus := "QUEUED_FOR_LOCAL_AGENT"
	if !created {
		queueStatus = "ALREADY_QUEUED"
	}

	providerResponse, err := json.Marshal(
		map[string]any{
			"status":            queueStatus,
			"provider":          p.Name(),
			"channel":           p.Channel(),
			"notification_code": message.Notification.NotificationCode,
			"delivery_id":       message.Delivery.ID.String(),
			"user_id":           message.Recipient.UserID.String(),
			"outbox_file":       destinationPath,
			"queued_at":         queuedAt,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode local desktop provider response: %w",
			err,
		)
	}

	// Writing to the outbox means the notification was sent to the
	// local desktop agent queue. The desktop agent must confirm the
	// final display before it can be considered delivered.
	providerMessageID := message.Delivery.ID.String()

	return &ProviderResult{
		ProviderName:      p.Name(),
		ProviderMessageID: &providerMessageID,
		ProviderResponse:  providerResponse,
		Delivered:         false,
		SentAt:            &queuedAt,
	}, nil
}

func localDesktopShouldPlaySound(severity string, priority int) bool {
	severity = strings.ToUpper(strings.TrimSpace(severity))
	return severity == SeverityHigh || severity == SeverityCritical || severity == SeverityMedium || priority >= PriorityHigh
}

func (p *LocalDesktopProvider) writeOutboxFile(
	ctx context.Context,
	directoryPath string,
	destinationPath string,
	content []byte,
) (bool, error) {
	if err := os.MkdirAll(
		directoryPath,
		p.config.DirectoryPermissions,
	); err != nil {
		return false, fmt.Errorf(
			"create local desktop outbox directory: %w",
			err,
		)
	}

	if _, err := os.Stat(destinationPath); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf(
			"inspect local desktop outbox file: %w",
			err,
		)
	}

	temporaryFile, err := os.CreateTemp(
		directoryPath,
		".ddh-desktop-*.tmp",
	)
	if err != nil {
		return false, fmt.Errorf(
			"create temporary local desktop notification: %w",
			err,
		)
	}

	temporaryPath := temporaryFile.Name()
	keepTemporaryFile := false

	defer func() {
		_ = temporaryFile.Close()

		if !keepTemporaryFile {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err = temporaryFile.Chmod(
		p.config.FilePermissions,
	); err != nil {
		return false, fmt.Errorf(
			"set local desktop notification permissions: %w",
			err,
		)
	}

	if err = ctx.Err(); err != nil {
		return false, err
	}

	if _, err = temporaryFile.Write(content); err != nil {
		return false, fmt.Errorf(
			"write local desktop notification: %w",
			err,
		)
	}

	if err = temporaryFile.Sync(); err != nil {
		return false, fmt.Errorf(
			"sync local desktop notification: %w",
			err,
		)
	}

	if err = temporaryFile.Close(); err != nil {
		return false, fmt.Errorf(
			"close local desktop notification: %w",
			err,
		)
	}

	if err = ctx.Err(); err != nil {
		return false, err
	}

	if _, err = os.Stat(destinationPath); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf(
			"recheck local desktop outbox file: %w",
			err,
		)
	}

	if err = os.Rename(
		temporaryPath,
		destinationPath,
	); err != nil {
		if _, statErr := os.Stat(destinationPath); statErr == nil {
			return false, nil
		}

		return false, fmt.Errorf(
			"publish local desktop notification: %w",
			err,
		)
	}

	keepTemporaryFile = true

	return true, nil
}

func localDesktopOptionalUUID(
	value *uuid.UUID,
) *string {
	if value == nil ||
		*value == uuid.Nil {
		return nil
	}

	normalizedValue := value.String()

	return &normalizedValue
}

func normalizeLocalDesktopPayload(
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
