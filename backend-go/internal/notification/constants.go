package notification

// Notification types identify the event that created a notification.
const (
	TypeThreatDetected        = "THREAT_DETECTED"
	TypeIncidentCreated       = "INCIDENT_CREATED"
	TypeIncidentAssigned      = "INCIDENT_ASSIGNED"
	TypeIncidentStatusChanged = "INCIDENT_STATUS_CHANGED"
	TypeEvidenceMismatch      = "EVIDENCE_MISMATCH"
	TypeHoneytokenAlert       = "HONEYTOKEN_ALERT"
	TypeCanaryFileAlert       = "CANARY_FILE_ALERT"
	TypeMediaAnalysisComplete = "MEDIA_ANALYSIS_COMPLETED"
	TypeEvidenceVerified      = "EVIDENCE_VERIFIED"
	TypeCaseAssigned          = "CASE_ASSIGNED"
	TypeReportApproval        = "REPORT_APPROVAL"
	TypeContainmentAction     = "CONTAINMENT_ACTION"
	TypeSystemAlert           = "SYSTEM_ALERT"
	TypeCustom                = "CUSTOM"
)

// Notification categories group related notification types.
const (
	CategorySecurity   = "SECURITY"
	CategoryIncident   = "INCIDENT"
	CategorySystem     = "SYSTEM"
	CategoryCompliance = "COMPLIANCE"
)

// Notification severity levels.
const (
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// Notification lifecycle statuses.
const (
	StatusCreated       = "CREATED"
	StatusQueued        = "QUEUED"
	StatusPartiallySent = "PARTIALLY_SENT"
	StatusSent          = "SENT"
	StatusFailed        = "FAILED"
	StatusCancelled     = "CANCELLED"
	StatusExpired       = "EXPIRED"
)

// Notification recipient types.
const (
	RecipientTypeUser     = "USER"
	RecipientTypeExternal = "EXTERNAL"
)

// In-app recipient statuses.
const (
	InAppStatusUnread       = "UNREAD"
	InAppStatusRead         = "READ"
	InAppStatusAcknowledged = "ACKNOWLEDGED"
	InAppStatusDismissed    = "DISMISSED"
)

// Notification delivery channels.
const (
	ChannelInApp        = "IN_APP"
	ChannelLocalDesktop = "LOCAL_DESKTOP"
	ChannelEmail        = "EMAIL"
	ChannelSMS          = "SMS"
	ChannelWebhook      = "WEBHOOK"
)

// Notification delivery statuses.
const (
	DeliveryStatusQueued         = "QUEUED"
	DeliveryStatusProcessing     = "PROCESSING"
	DeliveryStatusSent           = "SENT"
	DeliveryStatusDelivered      = "DELIVERED"
	DeliveryStatusFailed         = "FAILED"
	DeliveryStatusRetryScheduled = "RETRY_SCHEDULED"
	DeliveryStatusCancelled      = "CANCELLED"
	DeliveryStatusSkipped        = "SKIPPED"
)

// Notification priority values. Higher values are processed first.
const (
	PriorityLow      = 25
	PriorityMedium   = 50
	PriorityHigh     = 75
	PriorityCritical = 100
)

// Notification identifiers and worker defaults.
const (
	NotificationCodePrefix   = "DDH-NTF"
	DefaultMaximumAttempts   = 5
	DefaultNotificationLimit = 20
	MaximumNotificationLimit = 100
)
