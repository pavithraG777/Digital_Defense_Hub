package airisk

import (
	"time"

	"github.com/google/uuid"
)

const (
	RiskFeatureSchemaVersion = "1.0.0"

	RiskEngineRequestTypeIncidentRansomware = "INCIDENT_RANSOMWARE_RISK"
)

// IncidentRiskFeatures contains normalized incident,
// threat, file-event and evidence features supplied
// to the local Python AI Risk Scoring Engine.
type IncidentRiskFeatures struct {
	IncidentCategory string `json:"incident_category"`
	IncidentSeverity string `json:"incident_severity"`
	IncidentPriority string `json:"incident_priority"`
	IncidentStatus   string `json:"incident_status"`
	DetectionSource  string `json:"detection_source"`

	DataExposureSuspected bool `json:"data_exposure_suspected"`
	RansomwareSuspected   bool `json:"ransomware_suspected"`
	DeviceIsolated        bool `json:"device_isolated"`
	EvidencePreserved     bool `json:"evidence_preserved"`

	AffectedRecordCount      int64   `json:"affected_record_count"`
	EstimatedFinancialImpact float64 `json:"estimated_financial_impact"`

	IncidentAgeMinutes      float64 `json:"incident_age_minutes"`
	ReportingDelayMinutes   float64 `json:"reporting_delay_minutes"`
	InvestigationAgeMinutes float64 `json:"investigation_age_minutes"`

	LinkedThreatCount     int64 `json:"linked_threat_count"`
	CriticalThreatCount   int64 `json:"critical_threat_count"`
	HighThreatCount       int64 `json:"high_threat_count"`
	MaliciousThreatCount  int64 `json:"malicious_threat_count"`
	ConfirmedThreatCount  int64 `json:"confirmed_threat_count"`
	UnresolvedThreatCount int64 `json:"unresolved_threat_count"`

	MaximumThreatScore     float64 `json:"maximum_threat_score"`
	AverageThreatScore     float64 `json:"average_threat_score"`
	MaximumConfidenceScore float64 `json:"maximum_confidence_score"`

	TotalThreatOccurrences   int64 `json:"total_threat_occurrences"`
	TotalAffectedFileCount   int64 `json:"total_affected_file_count"`
	TotalAffectedDeviceCount int64 `json:"total_affected_device_count"`

	FileEventCount               int64 `json:"file_event_count"`
	SuspiciousFileEventCount     int64 `json:"suspicious_file_event_count"`
	EncryptedEventCount          int64 `json:"encrypted_event_count"`
	MultipleFileChangeEventCount int64 `json:"multiple_file_change_event_count"`
	HashChangeEventCount         int64 `json:"hash_change_event_count"`
	DeletedFileEventCount        int64 `json:"deleted_file_event_count"`
	PermissionChangeEventCount   int64 `json:"permission_change_event_count"`

	CanaryFileEventCount    int64 `json:"canary_file_event_count"`
	HoneytokenEventCount    int64 `json:"honeytoken_event_count"`
	ProtectedFileEventCount int64 `json:"protected_file_event_count"`

	UniqueDeviceCount  int64   `json:"unique_device_count"`
	EventWindowSeconds float64 `json:"event_window_seconds"`
	EventRatePerMinute float64 `json:"event_rate_per_minute"`

	EvidenceCount         int64 `json:"evidence_count"`
	VerifiedEvidenceCount int64 `json:"verified_evidence_count"`
	TamperedEvidenceCount int64 `json:"tampered_evidence_count"`

	HasCanaryTrigger        bool `json:"has_canary_trigger"`
	HasHoneytokenAccess     bool `json:"has_honeytoken_access"`
	HasEncryptionIndicators bool `json:"has_encryption_indicators"`
	HasRapidFileChanges     bool `json:"has_rapid_file_changes"`
	HasHashChanges          bool `json:"has_hash_changes"`
	HasFileDeletion         bool `json:"has_file_deletion"`
	HasPermissionChanges    bool `json:"has_permission_changes"`
}

// RiskEngineRequest is sent by Go to the local Python service.
type RiskEngineRequest struct {
	RequestID uuid.UUID `json:"request_id"`

	RequestType   string `json:"request_type"`
	SchemaVersion string `json:"schema_version"`

	OrganizationID uuid.UUID `json:"organization_id"`
	IncidentID     uuid.UUID `json:"incident_id"`

	Features IncidentRiskFeatures `json:"features"`

	RequestedAt time.Time `json:"requested_at"`
}

// RiskEngineResponse is returned by the local Python service.
type RiskEngineResponse struct {
	RequestID uuid.UUID `json:"request_id"`
	Success   bool      `json:"success"`

	Assessment *RiskEngineAssessment `json:"assessment,omitempty"`

	ErrorCode    *string `json:"error_code,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`

	ProcessedAt time.Time `json:"processed_at"`
}
