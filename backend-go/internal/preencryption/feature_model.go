package preencryption

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	DetectionFeatureSchemaVersion = "1.0.0"

	DetectionEngineRequestType = "PRE_ENCRYPTION_RANSOMWARE_ASSESSMENT"
)

// FileEventObservation contains the file-event fields used
// by the pre-encryption aggregation engine.
type FileEventObservation struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`

	DepartmentID    *uuid.UUID `json:"department_id,omitempty"`
	ProtectedFileID *uuid.UUID `json:"protected_file_id,omitempty"`
	HoneytokenID    *uuid.UUID `json:"honeytoken_id,omitempty"`
	CanaryFileID    *uuid.UUID `json:"canary_file_id,omitempty"`

	EventCode       string `json:"event_code"`
	SourceType      string `json:"source_type"`
	EventType       string `json:"event_type"`
	EventSource     string `json:"event_source"`
	DetectionMethod string `json:"detection_method"`

	FileName         string  `json:"file_name"`
	FilePath         string  `json:"file_path"`
	PreviousFilePath *string `json:"previous_file_path,omitempty"`
	FileExtension    *string `json:"file_extension,omitempty"`
	MimeType         *string `json:"mime_type,omitempty"`

	FileSizeBefore *int64 `json:"file_size_before,omitempty"`
	FileSizeAfter  *int64 `json:"file_size_after,omitempty"`

	PreviousHash *string `json:"previous_hash,omitempty"`
	CurrentHash  *string `json:"current_hash,omitempty"`

	ProcessID      *int64  `json:"process_id,omitempty"`
	ProcessName    *string `json:"process_name,omitempty"`
	ExecutablePath *string `json:"executable_path,omitempty"`

	ParentProcessID   *int64  `json:"parent_process_id,omitempty"`
	ParentProcessName *string `json:"parent_process_name,omitempty"`
	CommandLine       *string `json:"command_line,omitempty"`

	DeviceName       *string `json:"device_name,omitempty"`
	DeviceIdentifier *string `json:"device_identifier,omitempty"`

	Severity     string `json:"severity"`
	ThreatScore  int    `json:"threat_score"`
	IsSuspicious bool   `json:"is_suspicious"`

	Metadata json.RawMessage `json:"metadata"`

	OccurredAt time.Time `json:"occurred_at"`
}

// DetectionWindow contains events grouped by organization,
// device, process and time window.
type DetectionWindow struct {
	ID uuid.UUID `json:"id"`

	OrganizationID uuid.UUID  `json:"organization_id"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`

	DeviceIdentifier *string `json:"device_identifier,omitempty"`
	DeviceName       *string `json:"device_name,omitempty"`

	ProcessID      *int64  `json:"process_id,omitempty"`
	ProcessName    *string `json:"process_name,omitempty"`
	ExecutablePath *string `json:"executable_path,omitempty"`

	ParentProcessID   *int64  `json:"parent_process_id,omitempty"`
	ParentProcessName *string `json:"parent_process_name,omitempty"`
	CommandLine       *string `json:"command_line,omitempty"`

	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`

	Events []FileEventObservation `json:"events"`
}

// DetectionFeatures contains normalized behavioural features
// supplied to the Python scoring engine.
type DetectionFeatures struct {
	WindowDurationSeconds float64 `json:"window_duration_seconds"`

	TotalEventCount      int `json:"total_event_count"`
	UniqueFileCount      int `json:"unique_file_count"`
	UniqueExtensionCount int `json:"unique_extension_count"`
	UniqueProcessCount   int `json:"unique_process_count"`

	CreatedEventCount           int `json:"created_event_count"`
	ModifiedEventCount          int `json:"modified_event_count"`
	RenamedEventCount           int `json:"renamed_event_count"`
	ExtensionChangedEventCount  int `json:"extension_changed_event_count"`
	DeletedEventCount           int `json:"deleted_event_count"`
	HashChangedEventCount       int `json:"hash_changed_event_count"`
	PermissionChangedEventCount int `json:"permission_changed_event_count"`
	EncryptedEventCount         int `json:"encrypted_event_count"`

	MultipleFileChangeEventCount int `json:"multiple_file_change_event_count"`
	SuspiciousEventCount         int `json:"suspicious_event_count"`

	CanaryEventCount        int `json:"canary_event_count"`
	HoneytokenEventCount    int `json:"honeytoken_event_count"`
	ProtectedFileEventCount int `json:"protected_file_event_count"`

	HighEntropyWriteCount int   `json:"high_entropy_write_count"`
	TotalBytesChanged     int64 `json:"total_bytes_changed"`

	EventRatePerMinute      float64 `json:"event_rate_per_minute"`
	FileChangeRatePerMinute float64 `json:"file_change_rate_per_minute"`

	ModificationRatio    float64 `json:"modification_ratio"`
	RenameRatio          float64 `json:"rename_ratio"`
	ExtensionChangeRatio float64 `json:"extension_change_ratio"`
	DeletionRatio        float64 `json:"deletion_ratio"`
	HashChangeRatio      float64 `json:"hash_change_ratio"`
	SuspiciousEventRatio float64 `json:"suspicious_event_ratio"`

	AverageEntropyBefore *float64 `json:"average_entropy_before,omitempty"`
	AverageEntropyAfter  *float64 `json:"average_entropy_after,omitempty"`
	AverageEntropyDelta  *float64 `json:"average_entropy_delta,omitempty"`

	MaximumExistingThreatScore int `json:"maximum_existing_threat_score"`

	RansomwareExtensionCount int `json:"ransomware_extension_count"`
	SuspiciousProcessCount   int `json:"suspicious_process_count"`

	HasCanaryTrigger         bool `json:"has_canary_trigger"`
	HasHoneytokenAccess      bool `json:"has_honeytoken_access"`
	HasProtectedFileActivity bool `json:"has_protected_file_activity"`

	HasRapidFileChanges      bool `json:"has_rapid_file_changes"`
	HasMassModification      bool `json:"has_mass_modification"`
	HasRapidRename           bool `json:"has_rapid_rename"`
	HasExtensionChangeBurst  bool `json:"has_extension_change_burst"`
	HasDeletionBurst         bool `json:"has_deletion_burst"`
	HasHashChangeBurst       bool `json:"has_hash_change_burst"`
	HasPermissionChangeBurst bool `json:"has_permission_change_burst"`

	HasHighEntropyWrites   bool `json:"has_high_entropy_writes"`
	HasEncryptionActivity  bool `json:"has_encryption_activity"`
	HasRansomwareExtension bool `json:"has_ransomware_extension"`
	HasSuspiciousProcess   bool `json:"has_suspicious_process"`
}

// EventContribution links one event to the signals it
// contributed to in a detection.
type EventContribution struct {
	FileEventID uuid.UUID `json:"file_event_id"`

	SignalTypes []string `json:"signal_types"`

	ContributionScore float64 `json:"contribution_score"`
}

// DetectionEngineRequest is sent by Go to the local
// Python pre-encryption scoring service.
type DetectionEngineRequest struct {
	RequestID uuid.UUID `json:"request_id"`

	RequestType   string `json:"request_type"`
	SchemaVersion string `json:"schema_version"`

	OrganizationID uuid.UUID `json:"organization_id"`
	DetectionID    uuid.UUID `json:"detection_id"`

	WindowFingerprint string `json:"window_fingerprint"`

	RuleScore float64 `json:"rule_score"`

	Features DetectionFeatures `json:"features"`

	RequestedAt time.Time `json:"requested_at"`
}

// DetectionEngineAssessment is the validated result returned
// by the Python pre-encryption scoring engine.
type DetectionEngineAssessment struct {
	AIScore           float64 `json:"ai_score"`
	CombinedRiskScore float64 `json:"combined_risk_score"`

	ThreatProbability float64 `json:"threat_probability"`
	ConfidenceScore   float64 `json:"confidence_score"`

	RiskLevel      string `json:"risk_level"`
	Classification string `json:"classification"`
	DetectionStage string `json:"detection_stage"`

	RiskFactors []RiskFactor `json:"risk_factors"`

	RecommendedActions []RecommendedAction `json:"recommended_actions"`

	ScoreExplanation string `json:"score_explanation"`

	RequiresHumanReview       bool `json:"requires_human_review"`
	RequiresEndpointIsolation bool `json:"requires_endpoint_isolation"`

	ModelName     string `json:"model_name"`
	ModelVersion  string `json:"model_version"`
	PolicyVersion string `json:"policy_version"`
}

// DetectionEngineResponse is returned by the local
// Python pre-encryption scoring service.
type DetectionEngineResponse struct {
	RequestID uuid.UUID `json:"request_id"`
	Success   bool      `json:"success"`

	Assessment *DetectionEngineAssessment `json:"assessment,omitempty"`

	ErrorCode    *string `json:"error_code,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`

	ProcessedAt time.Time `json:"processed_at"`
}
