package preencryption

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Detection represents one aggregated pre-encryption
// ransomware behavioural assessment.
type Detection struct {
	ID                uuid.UUID `json:"id"`
	DetectionSequence int64     `json:"detection_sequence"`
	DetectionCode     string    `json:"detection_code"`

	DetectionFingerprint string `json:"detection_fingerprint"`

	OrganizationID uuid.UUID  `json:"organization_id"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`

	ThreatID   *uuid.UUID `json:"threat_id,omitempty"`
	IncidentID *uuid.UUID `json:"incident_id,omitempty"`

	DeviceIdentifier *string `json:"device_identifier,omitempty"`
	DeviceName       *string `json:"device_name,omitempty"`

	ProcessID      *int64  `json:"process_id,omitempty"`
	ProcessName    *string `json:"process_name,omitempty"`
	ExecutablePath *string `json:"executable_path,omitempty"`

	ParentProcessID   *int64  `json:"parent_process_id,omitempty"`
	ParentProcessName *string `json:"parent_process_name,omitempty"`
	CommandLine       *string `json:"command_line,omitempty"`

	WindowStartedAt       time.Time `json:"window_started_at"`
	WindowEndedAt         time.Time `json:"window_ended_at"`
	WindowDurationSeconds float64   `json:"window_duration_seconds"`

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

	CanaryEventCount        int `json:"canary_event_count"`
	HoneytokenEventCount    int `json:"honeytoken_event_count"`
	ProtectedFileEventCount int `json:"protected_file_event_count"`

	HighEntropyWriteCount int   `json:"high_entropy_write_count"`
	TotalBytesChanged     int64 `json:"total_bytes_changed"`

	EventRatePerMinute      float64 `json:"event_rate_per_minute"`
	FileChangeRatePerMinute float64 `json:"file_change_rate_per_minute"`

	AverageEntropyBefore *float64 `json:"average_entropy_before,omitempty"`
	AverageEntropyAfter  *float64 `json:"average_entropy_after,omitempty"`
	AverageEntropyDelta  *float64 `json:"average_entropy_delta,omitempty"`

	RuleScore         float64  `json:"rule_score"`
	AIScore           *float64 `json:"ai_score,omitempty"`
	CombinedRiskScore float64  `json:"combined_risk_score"`
	ThreatProbability *float64 `json:"threat_probability,omitempty"`
	ConfidenceScore   *float64 `json:"confidence_score,omitempty"`

	RiskLevel       string `json:"risk_level"`
	Classification  string `json:"classification"`
	DetectionStage  string `json:"detection_stage"`
	DetectionMethod string `json:"detection_method"`

	RiskFactors        json.RawMessage `json:"risk_factors"`
	RecommendedActions json.RawMessage `json:"recommended_actions"`
	ScoreExplanation   *string         `json:"score_explanation,omitempty"`

	ModelName     *string `json:"model_name,omitempty"`
	ModelVersion  *string `json:"model_version,omitempty"`
	PolicyVersion *string `json:"policy_version,omitempty"`

	RequiresHumanReview       bool `json:"requires_human_review"`
	RequiresEndpointIsolation bool `json:"requires_endpoint_isolation"`

	Status       string `json:"status"`
	ActionStatus string `json:"action_status"`

	Metadata json.RawMessage `json:"metadata"`

	DetectedAt  time.Time  `json:"detected_at"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	MitigatedAt *time.Time `json:"mitigated_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DetectionEvent links a detection to one file event
// that contributed to the ransomware assessment.
type DetectionEvent struct {
	ID uuid.UUID `json:"id"`

	OrganizationID uuid.UUID `json:"organization_id"`
	DetectionID    uuid.UUID `json:"detection_id"`
	FileEventID    uuid.UUID `json:"file_event_id"`

	SignalTypes       json.RawMessage `json:"signal_types"`
	ContributionScore float64         `json:"contribution_score"`

	LinkedAt time.Time `json:"linked_at"`
}
