package honeytoken

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ThreatListQuery represents supported threat list query parameters.
type ThreatListQuery struct {
	DepartmentID    string `form:"department_id" binding:"omitempty,uuid"`
	ThreatType      string `form:"threat_type"`
	Category        string `form:"category"`
	Severity        string `form:"severity"`
	Classification  string `form:"classification"`
	Status          string `form:"status"`
	DetectionMethod string `form:"detection_method"`
	Search          string `form:"search" binding:"omitempty,max=200"`
	From            string `form:"from"`
	To              string `form:"to"`
	Page            int    `form:"page" binding:"omitempty,min=1"`
	PageSize        int    `form:"page_size" binding:"omitempty,min=1,max=100"`
}

// ThreatFilter is the validated repository filter used for threat queries.
type ThreatFilter struct {
	OrganizationID  uuid.UUID
	DepartmentID    *uuid.UUID
	ThreatType      string
	Category        string
	Severity        string
	Classification  string
	Status          string
	DetectionMethod string
	Search          string
	From            *time.Time
	To              *time.Time
	Limit           int
	Offset          int
}

// UpdateThreatStatusRequest represents a threat lifecycle status update.
type UpdateThreatStatusRequest struct {
	Status          string  `json:"status" binding:"required"`
	ResolutionNotes *string `json:"resolution_notes,omitempty" binding:"omitempty,max=4000"`
}

// AssignThreatRequest represents assignment of a threat to an investigator.
type AssignThreatRequest struct {
	AssignedTo string `json:"assigned_to" binding:"required,uuid"`
}

// ThreatFileEventResponse represents an event correlated with a threat.
type ThreatFileEventResponse struct {
	FileEventID  string    `json:"file_event_id"`
	RelationType string    `json:"relation_type"`
	CreatedAt    time.Time `json:"created_at"`
}

// ThreatResponse represents a threat returned by the API.
type ThreatResponse struct {
	ID                 string                    `json:"id"`
	ThreatSequence     int64                     `json:"threat_sequence"`
	ThreatCode         string                    `json:"threat_code"`
	CorrelationKey     *string                   `json:"correlation_key,omitempty"`
	OrganizationID     string                    `json:"organization_id"`
	DepartmentID       *string                   `json:"department_id,omitempty"`
	PrimaryFileEventID *string                   `json:"primary_file_event_id,omitempty"`
	MonitoringRuleID   *string                   `json:"monitoring_rule_id,omitempty"`
	ProtectedFileID    *string                   `json:"protected_file_id,omitempty"`
	HoneytokenID       *string                   `json:"honeytoken_id,omitempty"`
	CanaryFileID       *string                   `json:"canary_file_id,omitempty"`
	ThreatType         string                    `json:"threat_type"`
	ThreatCategory     string                    `json:"threat_category"`
	DetectionMethod    string                    `json:"detection_method"`
	Title              string                    `json:"title"`
	Description        *string                   `json:"description,omitempty"`
	Severity           string                    `json:"severity"`
	ThreatScore        int                       `json:"threat_score"`
	ConfidenceScore    float64                   `json:"confidence_score"`
	Classification     string                    `json:"classification"`
	Status             string                    `json:"status"`
	EventCount         int                       `json:"event_count"`
	AffectedFileCount  int                       `json:"affected_file_count"`
	FirstDetectedAt    time.Time                 `json:"first_detected_at"`
	LastDetectedAt     time.Time                 `json:"last_detected_at"`
	ProcessName        *string                   `json:"process_name,omitempty"`
	ProcessID          *int64                    `json:"process_id,omitempty"`
	ProcessPath        *string                   `json:"process_path,omitempty"`
	DeviceName         *string                   `json:"device_name,omitempty"`
	DeviceIdentifier   *string                   `json:"device_identifier,omitempty"`
	SourceIPAddress    *string                   `json:"source_ip_address,omitempty"`
	Indicators         json.RawMessage           `json:"indicators,omitempty"`
	RiskFactors        json.RawMessage           `json:"risk_factors,omitempty"`
	EvidenceSummary    json.RawMessage           `json:"evidence_summary,omitempty"`
	RecommendedActions json.RawMessage           `json:"recommended_actions,omitempty"`
	ContainmentActions json.RawMessage           `json:"containment_actions,omitempty"`
	ResolutionNotes    *string                   `json:"resolution_notes,omitempty"`
	AssignedTo         *string                   `json:"assigned_to,omitempty"`
	ConfirmedBy        *string                   `json:"confirmed_by,omitempty"`
	ResolvedBy         *string                   `json:"resolved_by,omitempty"`
	ConfirmedAt        *time.Time                `json:"confirmed_at,omitempty"`
	MitigatedAt        *time.Time                `json:"mitigated_at,omitempty"`
	ResolvedAt         *time.Time                `json:"resolved_at,omitempty"`
	CreatedAt          time.Time                 `json:"created_at"`
	UpdatedAt          time.Time                 `json:"updated_at"`
	FileEvents         []ThreatFileEventResponse `json:"file_events,omitempty"`
}

// ThreatListResponse represents a paginated threat collection.
type ThreatListResponse struct {
	Threats    []ThreatResponse `json:"threats"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

// ThreatDetectionResult represents the output of processing a file event.
type ThreatDetectionResult struct {
	ThreatCreated bool            `json:"threat_created"`
	Threat        *ThreatResponse `json:"threat,omitempty"`
	Reason        string          `json:"reason"`
}
