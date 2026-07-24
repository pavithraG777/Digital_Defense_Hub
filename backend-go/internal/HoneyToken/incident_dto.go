package honeytoken

import (
	"time"

	"github.com/google/uuid"
)

// CreateIncidentRequest represents a manually reported security incident.
// Organization and reporter IDs are obtained from the authenticated JWT.
type CreateIncidentRequest struct {
	DepartmentID *string `json:"department_id" binding:"omitempty,uuid"`

	IncidentTitle    string  `json:"incident_title" binding:"required,min=3,max=255"`
	Description      *string `json:"description,omitempty" binding:"omitempty,max=5000"`
	IncidentCategory string  `json:"incident_category" binding:"required,oneof=UNAUTHORIZED_ACCESS HONEYTOKEN_TRIGGER CANARY_FILE_TRIGGER RANSOMWARE MALWARE PHISHING DATA_BREACH INSIDER_THREAT ACCOUNT_COMPROMISE API_ATTACK DEEPFAKE DIGITAL_EVIDENCE POLICY_VIOLATION SYSTEM_ANOMALY OTHER"`
	Severity         string  `json:"severity" binding:"omitempty,oneof=LOW MEDIUM HIGH CRITICAL"`
	Priority         string  `json:"priority" binding:"omitempty,oneof=LOW MEDIUM HIGH URGENT"`
	DetectionSource  string  `json:"detection_source" binding:"required,oneof=SECURITY_ALERT HONEYTOKEN CANARY_FILE FILE_MONITORING AI_ANALYSIS USER_REPORT ADMIN_REPORT SYSTEM EXTERNAL_REPORT OTHER"`

	AffectedUserID           *string `json:"affected_user_id,omitempty" binding:"omitempty,uuid"`
	AffectedDeviceName       *string `json:"affected_device_name,omitempty" binding:"omitempty,max=255"`
	AffectedDeviceIdentifier *string `json:"affected_device_identifier,omitempty" binding:"omitempty,max=255"`
	LeadInvestigatorID       *string `json:"lead_investigator_id,omitempty" binding:"omitempty,uuid"`

	DataExposureSuspected bool `json:"data_exposure_suspected"`
	RansomwareSuspected   bool `json:"ransomware_suspected"`
	DeviceIsolated        bool `json:"device_isolated"`
	EvidencePreserved     bool `json:"evidence_preserved"`

	AffectedRecordCount      *int64   `json:"affected_record_count,omitempty" binding:"omitempty,gte=0"`
	EstimatedFinancialImpact *float64 `json:"estimated_financial_impact,omitempty" binding:"omitempty,gte=0"`

	InitialFindings *string `json:"initial_findings,omitempty" binding:"omitempty,max=10000"`
	DetectedAt      *string `json:"detected_at,omitempty"`
}

// IncidentListQuery represents supported incident list query parameters.
type IncidentListQuery struct {
	DepartmentID       string `form:"department_id" binding:"omitempty,uuid"`
	IncidentCategory   string `form:"incident_category"`
	Severity           string `form:"severity"`
	Priority           string `form:"priority"`
	Status             string `form:"status"`
	DetectionSource    string `form:"detection_source"`
	LeadInvestigatorID string `form:"lead_investigator_id" binding:"omitempty,uuid"`
	Search             string `form:"search" binding:"omitempty,max=200"`
	From               string `form:"from"`
	To                 string `form:"to"`
	Page               int    `form:"page" binding:"omitempty,min=1"`
	PageSize           int    `form:"page_size" binding:"omitempty,min=1,max=100"`
}

// IncidentFilter is the validated, tenant-isolated repository filter.
type IncidentFilter struct {
	OrganizationID     uuid.UUID
	DepartmentID       *uuid.UUID
	IncidentCategory   string
	Severity           string
	Priority           string
	Status             string
	DetectionSource    string
	LeadInvestigatorID *uuid.UUID
	Search             string
	From               *time.Time
	To                 *time.Time
	Limit              int
	Offset             int
}

// AssignIncidentRequest assigns or reassigns an incident investigation.
type AssignIncidentRequest struct {
	LeadInvestigatorID string `json:"lead_investigator_id" binding:"required,uuid"`
}

// UpdateIncidentStatusRequest represents an incident lifecycle transition.
type UpdateIncidentStatusRequest struct {
	Status             string  `json:"status" binding:"required,oneof=OPEN ASSIGNED INVESTIGATING CONTAINED ERADICATED RECOVERING RESOLVED CLOSED REOPENED CANCELLED"`
	ContainmentSummary *string `json:"containment_summary,omitempty" binding:"omitempty,max=10000"`
	ResolutionSummary  *string `json:"resolution_summary,omitempty" binding:"omitempty,max=10000"`
}

// UpdateIncidentInvestigationRequest updates investigation findings and
// containment-related information without changing incident ownership.
type UpdateIncidentInvestigationRequest struct {
	InitialFindings    *string `json:"initial_findings,omitempty" binding:"omitempty,max=10000"`
	RootCause          *string `json:"root_cause,omitempty" binding:"omitempty,max=10000"`
	ContainmentSummary *string `json:"containment_summary,omitempty" binding:"omitempty,max=10000"`
	ResolutionSummary  *string `json:"resolution_summary,omitempty" binding:"omitempty,max=10000"`

	DataExposureSuspected *bool `json:"data_exposure_suspected,omitempty"`
	RansomwareSuspected   *bool `json:"ransomware_suspected,omitempty"`
	DeviceIsolated        *bool `json:"device_isolated,omitempty"`
	EvidencePreserved     *bool `json:"evidence_preserved,omitempty"`

	AffectedRecordCount      *int64   `json:"affected_record_count,omitempty" binding:"omitempty,gte=0"`
	EstimatedFinancialImpact *float64 `json:"estimated_financial_impact,omitempty" binding:"omitempty,gte=0"`
}

// IncidentResponse represents incident information returned by the API.
type IncidentResponse struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	DepartmentID   *string `json:"department_id,omitempty"`

	IncidentNumber   string  `json:"incident_number"`
	IncidentTitle    string  `json:"incident_title"`
	Description      *string `json:"description,omitempty"`
	IncidentCategory string  `json:"incident_category"`
	Severity         string  `json:"severity"`
	Priority         string  `json:"priority"`
	Status           string  `json:"status"`
	DetectionSource  string  `json:"detection_source"`

	AffectedUserID           *string `json:"affected_user_id,omitempty"`
	AffectedDeviceName       *string `json:"affected_device_name,omitempty"`
	AffectedDeviceIdentifier *string `json:"affected_device_identifier,omitempty"`
	LeadInvestigatorID       *string `json:"lead_investigator_id,omitempty"`
	ReportedBy               *string `json:"reported_by,omitempty"`

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

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IncidentListResponse represents a paginated incident collection.
type IncidentListResponse struct {
	Incidents  []IncidentResponse `json:"incidents"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}
