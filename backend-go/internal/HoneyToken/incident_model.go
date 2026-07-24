package honeytoken

import (
	"time"

	"github.com/google/uuid"
)

// Incident represents a confirmed or suspected security incident managed by
// the Digital Defense Hub incident-response workflow.
type Incident struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`

	IncidentNumber   string  `json:"incident_number"`
	IncidentTitle    string  `json:"incident_title"`
	Description      *string `json:"description,omitempty"`
	IncidentCategory string  `json:"incident_category"`
	Severity         string  `json:"severity"`
	Priority         string  `json:"priority"`
	Status           string  `json:"status"`
	DetectionSource  string  `json:"detection_source"`

	AffectedUserID           *uuid.UUID `json:"affected_user_id,omitempty"`
	AffectedDeviceName       *string    `json:"affected_device_name,omitempty"`
	AffectedDeviceIdentifier *string    `json:"affected_device_identifier,omitempty"`

	LeadInvestigatorID *uuid.UUID `json:"lead_investigator_id,omitempty"`
	ReportedBy         *uuid.UUID `json:"reported_by,omitempty"`

	DataExposureSuspected bool `json:"data_exposure_suspected"`
	RansomwareSuspected   bool `json:"ransomware_suspected"`
	DeviceIsolated        bool `json:"device_isolated"`
	EvidencePreserved     bool `json:"evidence_preserved"`

	AffectedRecordCount      *int64   `json:"affected_record_count,omitempty"`
	EstimatedFinancialImpact *float64 `json:"estimated_financial_impact,omitempty"`

	InitialFindings    *string `json:"initial_findings,omitempty"`
	RootCause          *string `json:"root_cause,omitempty"`
	ContainmentSummary *string `json:"containment_summary,omitempty"`
	ResolutionSummary  *string `json:"resolution_summary,omitempty"`

	DetectedAt             time.Time  `json:"detected_at"`
	ReportedAt             time.Time  `json:"reported_at"`
	InvestigationStartedAt *time.Time `json:"investigation_started_at,omitempty"`
	ContainedAt            *time.Time `json:"contained_at,omitempty"`
	ResolvedAt             *time.Time `json:"resolved_at,omitempty"`
	ClosedAt               *time.Time `json:"closed_at,omitempty"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}
