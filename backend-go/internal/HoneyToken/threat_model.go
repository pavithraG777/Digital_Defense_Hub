package honeytoken

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Threat represents a correlated security threat detected from one or more
// file events.
type Threat struct {
	ID                 uuid.UUID       `json:"id"`
	ThreatSequence     int64           `json:"threat_sequence"`
	ThreatCode         string          `json:"threat_code"`
	CorrelationKey     *string         `json:"correlation_key,omitempty"`
	OrganizationID     uuid.UUID       `json:"organization_id"`
	DepartmentID       *uuid.UUID      `json:"department_id,omitempty"`
	PrimaryFileEventID *uuid.UUID      `json:"primary_file_event_id,omitempty"`
	MonitoringRuleID   *uuid.UUID      `json:"monitoring_rule_id,omitempty"`
	ProtectedFileID    *uuid.UUID      `json:"protected_file_id,omitempty"`
	HoneytokenID       *uuid.UUID      `json:"honeytoken_id,omitempty"`
	CanaryFileID       *uuid.UUID      `json:"canary_file_id,omitempty"`
	ThreatType         string          `json:"threat_type"`
	ThreatCategory     string          `json:"threat_category"`
	DetectionMethod    string          `json:"detection_method"`
	Title              string          `json:"title"`
	Description        *string         `json:"description,omitempty"`
	Severity           string          `json:"severity"`
	ThreatScore        int             `json:"threat_score"`
	ConfidenceScore    float64         `json:"confidence_score"`
	Classification     string          `json:"classification"`
	Status             string          `json:"status"`
	EventCount         int             `json:"event_count"`
	AffectedFileCount  int             `json:"affected_file_count"`
	FirstDetectedAt    time.Time       `json:"first_detected_at"`
	LastDetectedAt     time.Time       `json:"last_detected_at"`
	ProcessName        *string         `json:"process_name,omitempty"`
	ProcessID          *int64          `json:"process_id,omitempty"`
	ProcessPath        *string         `json:"process_path,omitempty"`
	DeviceName         *string         `json:"device_name,omitempty"`
	DeviceIdentifier   *string         `json:"device_identifier,omitempty"`
	SourceIPAddress    *string         `json:"source_ip_address,omitempty"`
	Indicators         json.RawMessage `json:"indicators,omitempty"`
	RiskFactors        json.RawMessage `json:"risk_factors,omitempty"`
	EvidenceSummary    json.RawMessage `json:"evidence_summary,omitempty"`
	RecommendedActions json.RawMessage `json:"recommended_actions,omitempty"`
	ContainmentActions json.RawMessage `json:"containment_actions,omitempty"`
	ResolutionNotes    *string         `json:"resolution_notes,omitempty"`
	AssignedTo         *uuid.UUID      `json:"assigned_to,omitempty"`
	ConfirmedBy        *uuid.UUID      `json:"confirmed_by,omitempty"`
	ResolvedBy         *uuid.UUID      `json:"resolved_by,omitempty"`
	ConfirmedAt        *time.Time      `json:"confirmed_at,omitempty"`
	MitigatedAt        *time.Time      `json:"mitigated_at,omitempty"`
	ResolvedAt         *time.Time      `json:"resolved_at,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
	DeletedAt          *time.Time      `json:"deleted_at,omitempty"`
}

// ThreatFileEvent represents the relationship between a threat and the file
// events used to detect, correlate, or prove that threat.
type ThreatFileEvent struct {
	ThreatID     uuid.UUID `json:"threat_id"`
	FileEventID  uuid.UUID `json:"file_event_id"`
	RelationType string    `json:"relation_type"`
	CreatedAt    time.Time `json:"created_at"`
}
