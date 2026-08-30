package notification

import (
	"encoding/json"
	"time"
)

// CreateRecipientRequest defines one internal or external recipient.
type CreateRecipientRequest struct {
	RecipientType string  `json:"recipient_type" binding:"required,oneof=USER EXTERNAL"`
	UserID        *string `json:"user_id,omitempty" binding:"omitempty,uuid"`

	RecipientName *string `json:"recipient_name,omitempty" binding:"omitempty,max=255"`
	EmailAddress  *string `json:"email_address,omitempty" binding:"omitempty,email,max=320"`
	PhoneNumber   *string `json:"phone_number,omitempty" binding:"omitempty,max=30"`

	Channels []string `json:"channels" binding:"required,min=1,dive,oneof=IN_APP LOCAL_DESKTOP EMAIL SMS WEBHOOK"`
}

// CreateNotificationRequest defines an administrator or internal service
// notification request.
type CreateNotificationRequest struct {
	DepartmentID *string `json:"department_id,omitempty" binding:"omitempty,uuid"`
	IncidentID   *string `json:"incident_id,omitempty" binding:"omitempty,uuid"`
	ThreatID     *string `json:"threat_id,omitempty" binding:"omitempty,uuid"`

	NotificationType string `json:"notification_type" binding:"required,oneof=THREAT_DETECTED INCIDENT_CREATED INCIDENT_ASSIGNED INCIDENT_STATUS_CHANGED EVIDENCE_MISMATCH HONEYTOKEN_ALERT CANARY_FILE_ALERT MEDIA_ANALYSIS_COMPLETED EVIDENCE_VERIFIED CASE_ASSIGNED REPORT_APPROVAL CONTAINMENT_ACTION SYSTEM_ALERT CUSTOM"`
	Category         string `json:"category" binding:"omitempty,oneof=SECURITY INCIDENT SYSTEM COMPLIANCE"`

	Title    string `json:"title" binding:"required,min=3,max=255"`
	Message  string `json:"message" binding:"required,min=3,max=10000"`
	Severity string `json:"severity" binding:"omitempty,oneof=LOW MEDIUM HIGH CRITICAL"`

	PriorityLevel *int `json:"priority_level,omitempty" binding:"omitempty,min=1,max=100"`

	DeduplicationKey *string         `json:"deduplication_key,omitempty" binding:"omitempty,max=128"`
	Payload          json.RawMessage `json:"payload,omitempty"`

	RequiresAcknowledgement bool `json:"requires_acknowledgement"`

	Recipients []CreateRecipientRequest `json:"recipients" binding:"required,min=1,dive"`

	ScheduledAt *string `json:"scheduled_at,omitempty"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

// NotificationListQuery represents organization notification filters.
type NotificationListQuery struct {
	DepartmentID     string `form:"department_id" binding:"omitempty,uuid"`
	IncidentID       string `form:"incident_id" binding:"omitempty,uuid"`
	ThreatID         string `form:"threat_id" binding:"omitempty,uuid"`
	NotificationType string `form:"notification_type"`
	Severity         string `form:"severity"`
	Status           string `form:"status"`
	Search           string `form:"search" binding:"omitempty,max=200"`
	From             string `form:"from"`
	To               string `form:"to"`
	Page             int    `form:"page" binding:"omitempty,min=1"`
	PageSize         int    `form:"page_size" binding:"omitempty,min=1,max=100"`
}

// UserNotificationListQuery represents current-user in-app filters.
type UserNotificationListQuery struct {
	InAppStatus string `form:"in_app_status"`
	Severity    string `form:"severity"`
	Page        int    `form:"page" binding:"omitempty,min=1"`
	PageSize    int    `form:"page_size" binding:"omitempty,min=1,max=100"`
}

// NotificationRecipientResponse returns safe recipient delivery metadata.
type NotificationRecipientResponse struct {
	ID            string  `json:"id"`
	RecipientType string  `json:"recipient_type"`
	UserID        *string `json:"user_id,omitempty"`
	RecipientName *string `json:"recipient_name,omitempty"`
	EmailAddress  *string `json:"email_address,omitempty"`
	PhoneNumber   *string `json:"phone_number,omitempty"`
	InAppStatus   string  `json:"in_app_status"`

	ReadAt         *time.Time `json:"read_at,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	DismissedAt    *time.Time `json:"dismissed_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NotificationDeliveryResponse returns delivery status without exposing
// provider secrets.
type NotificationDeliveryResponse struct {
	ID             string `json:"id"`
	RecipientID    string `json:"recipient_id"`
	Channel        string `json:"channel"`
	DeliveryStatus string `json:"delivery_status"`

	AttemptCount    int `json:"attempt_count"`
	MaximumAttempts int `json:"maximum_attempts"`

	ProviderName      *string `json:"provider_name,omitempty"`
	ProviderMessageID *string `json:"provider_message_id,omitempty"`
	LastError         *string `json:"last_error,omitempty"`

	ScheduledAt         time.Time  `json:"scheduled_at"`
	NextRetryAt         *time.Time `json:"next_retry_at,omitempty"`
	ProcessingStartedAt *time.Time `json:"processing_started_at,omitempty"`
	SentAt              *time.Time `json:"sent_at,omitempty"`
	DeliveredAt         *time.Time `json:"delivered_at,omitempty"`
	FailedAt            *time.Time `json:"failed_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NotificationResponse represents a notification returned by the API.
type NotificationResponse struct {
	ID                   string `json:"id"`
	NotificationSequence int64  `json:"notification_sequence"`
	NotificationCode     string `json:"notification_code"`

	OrganizationID string  `json:"organization_id"`
	DepartmentID   *string `json:"department_id,omitempty"`
	IncidentID     *string `json:"incident_id,omitempty"`
	ThreatID       *string `json:"threat_id,omitempty"`

	NotificationType string `json:"notification_type"`
	Category         string `json:"category"`
	Title            string `json:"title"`
	Message          string `json:"message"`
	Severity         string `json:"severity"`
	PriorityLevel    int    `json:"priority_level"`

	Payload json.RawMessage `json:"payload,omitempty"`

	RequiresAcknowledgement bool       `json:"requires_acknowledgement"`
	AcknowledgedBy          *string    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt          *time.Time `json:"acknowledged_at,omitempty"`

	Status string `json:"status"`

	CreatedBy   *string    `json:"created_by,omitempty"`
	ScheduledAt *time.Time `json:"scheduled_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Recipients []NotificationRecipientResponse `json:"recipients,omitempty"`
	Deliveries []NotificationDeliveryResponse  `json:"deliveries,omitempty"`
}

// UserNotificationResponse combines an in-app notification with the current
// user's read state.
type UserNotificationResponse struct {
	Notification NotificationResponse `json:"notification"`
	RecipientID  string               `json:"recipient_id"`
	InAppStatus  string               `json:"in_app_status"`

	ReadAt         *time.Time `json:"read_at,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	DismissedAt    *time.Time `json:"dismissed_at,omitempty"`
}

// NotificationListResponse represents paginated organization notifications.
type NotificationListResponse struct {
	Notifications []NotificationResponse `json:"notifications"`
	Total         int64                  `json:"total"`
	Page          int                    `json:"page"`
	PageSize      int                    `json:"page_size"`
	TotalPages    int                    `json:"total_pages"`
}

// UserNotificationListResponse represents paginated current-user in-app
// notifications.
type UserNotificationListResponse struct {
	Notifications []UserNotificationResponse `json:"notifications"`
	UnreadCount   int64                      `json:"unread_count"`
	Total         int64                      `json:"total"`
	Page          int                        `json:"page"`
	PageSize      int                        `json:"page_size"`
	TotalPages    int                        `json:"total_pages"`
}
