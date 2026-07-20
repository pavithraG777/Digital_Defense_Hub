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
