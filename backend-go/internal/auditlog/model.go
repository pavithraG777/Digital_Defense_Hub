package auditlog

import (
	"time"

	"github.com/google/uuid"
)

type AuditLog struct {
	ID uuid.UUID `db:"id"`

	OrganizationID *uuid.UUID `db:"organization_id"`
	UserID         *uuid.UUID `db:"user_id"`
	SessionID      *uuid.UUID `db:"session_id"`

	ModuleName string `db:"module_name"`
	ActionName string `db:"action_name"`

	EntityType string     `db:"entity_type"`
	EntityID   *uuid.UUID `db:"entity_id"`

	Description string `db:"description"`

	OldValues map[string]any `db:"old_values"`
	NewValues map[string]any `db:"new_values"`
	Metadata  map[string]any `db:"metadata"`

	IPAddress string `db:"ip_address"`

	DeviceName string `db:"device_name"`
	UserAgent  string `db:"user_agent"`

	ResultStatus string `db:"result_status"`

	RiskLevel string `db:"risk_level"`

	FailureReason string `db:"failure_reason"`

	OccurredAt time.Time `db:"occurred_at"`
	CreatedAt  time.Time `db:"created_at"`
}

// TimelineEvent is the normalized, safe-to-display representation used by the
// central activity feed.  It deliberately contains no raw evidence, command
// line, IP address, or audit metadata.
type TimelineEvent struct {
	ID          string    `json:"id"`
	SourceType  string    `json:"source_type"`
	EventCode   string    `json:"event_code"`
	EventType   string    `json:"event_type"`
	EventSource string    `json:"event_source"`
	Resource    string    `json:"resource"`
	Actor       string    `json:"actor"`
	DeviceName  string    `json:"device_name"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	OccurredAt  time.Time `json:"occurred_at"`
}

type TimelineFilter struct {
	Search     string
	SourceType string
	RiskLevel  string
	Suspicious bool
	From       *time.Time
	To         *time.Time
	Limit      int
	Offset     int
}

type TimelinePage struct {
	Items []TimelineEvent `json:"items"`
	Total int             `json:"total"`
}
