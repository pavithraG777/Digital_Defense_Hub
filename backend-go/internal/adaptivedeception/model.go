package adaptivedeception

import (
	"time"

	"github.com/google/uuid"
)

// CanaryHealthCheck represents one persisted canary-file
// integrity and availability health check.
type CanaryHealthCheck struct {
	ID                  uuid.UUID `json:"id"`
	HealthCheckSequence int64     `json:"health_check_sequence"`

	OrganizationID uuid.UUID  `json:"organization_id"`
	CanaryFileID   uuid.UUID  `json:"canary_file_id"`
	PolicyID       *uuid.UUID `json:"policy_id,omitempty"`

	CheckType string `json:"check_type"`

	ExpectedFilePath string  `json:"expected_file_path"`
	ObservedFilePath *string `json:"observed_file_path,omitempty"`

	ExpectedHash string  `json:"expected_hash"`
	ObservedHash *string `json:"observed_hash,omitempty"`

	HashAlgorithm string `json:"hash_algorithm"`

	ExpectedSizeBytes *int64 `json:"expected_size_bytes,omitempty"`
	ObservedSizeBytes *int64 `json:"observed_size_bytes,omitempty"`

	FileExists       bool `json:"file_exists"`
	PathMatches      bool `json:"path_matches"`
	HashMatches      bool `json:"hash_matches"`
	SizeMatches      bool `json:"size_matches"`
	PermissionsValid bool `json:"permissions_valid"`

	IsHealthy    bool    `json:"is_healthy"`
	HealthScore  float64 `json:"health_score"`
	HealthStatus string  `json:"health_status"`

	FailureReason *string `json:"failure_reason,omitempty"`

	Metadata map[string]any `json:"metadata"`

	CheckedAt   time.Time  `json:"checked_at"`
	NextCheckAt *time.Time `json:"next_check_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CanaryRotation represents one canary rotation request
// and its execution result.
type CanaryRotation struct {
	ID               uuid.UUID `json:"id"`
	RotationSequence int64     `json:"rotation_sequence"`

	OrganizationID uuid.UUID  `json:"organization_id"`
	CanaryFileID   uuid.UUID  `json:"canary_file_id"`
	PolicyID       *uuid.UUID `json:"policy_id,omitempty"`

	RotationReason   string `json:"rotation_reason"`
	RotationStrategy string `json:"rotation_strategy"`

	OldFileName           *string `json:"old_file_name,omitempty"`
	NewFileName           *string `json:"new_file_name,omitempty"`
	OldFilePath           *string `json:"old_file_path,omitempty"`
	NewFilePath           *string `json:"new_file_path,omitempty"`
	OldFileHash           *string `json:"old_file_hash,omitempty"`
	NewFileHash           *string `json:"new_file_hash,omitempty"`
	OldTrackingIdentifier *string `json:"old_tracking_identifier,omitempty"`
	NewTrackingIdentifier *string `json:"new_tracking_identifier,omitempty"`

	Status string `json:"status"`

	RequestedBy  *uuid.UUID `json:"requested_by,omitempty"`
	ErrorMessage *string    `json:"error_message,omitempty"`

	Metadata map[string]any `json:"metadata"`

	RequestedAt time.Time  `json:"requested_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	FailedAt    *time.Time `json:"failed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// CanaryInteractionFingerprint represents a normalized,
// repeatable fingerprint generated from canary interaction data.
type CanaryInteractionFingerprint struct {
	ID                  uuid.UUID `json:"id"`
	FingerprintSequence int64     `json:"fingerprint_sequence"`

	OrganizationID uuid.UUID `json:"organization_id"`
	CanaryFileID   uuid.UUID `json:"canary_file_id"`

	AccessLogID *uuid.UUID `json:"access_log_id,omitempty"`
	FileEventID *uuid.UUID `json:"file_event_id,omitempty"`

	FingerprintHash    string `json:"fingerprint_hash"`
	FingerprintVersion string `json:"fingerprint_version"`

	EventType string `json:"event_type"`

	DeviceIdentifier *string `json:"device_identifier,omitempty"`
	DeviceName       *string `json:"device_name,omitempty"`

	OperatingSystem     *string `json:"operating_system,omitempty"`
	OperatingSystemUser *string `json:"operating_system_user,omitempty"`

	ProcessName       *string `json:"process_name,omitempty"`
	ProcessPath       *string `json:"process_path,omitempty"`
	ProcessID         *int64  `json:"process_id,omitempty"`
	ParentProcessName *string `json:"parent_process_name,omitempty"`

	SourceIP *string `json:"source_ip,omitempty"`

	InteractionPattern map[string]any `json:"interaction_pattern"`

	BehaviouralScore float64 `json:"behavioural_score"`
	ConfidenceScore  float64 `json:"confidence_score"`

	IsSuspicious        bool `json:"is_suspicious"`
	RansomwareSuspected bool `json:"ransomware_suspected"`

	OccurrenceCount int `json:"occurrence_count"`

	FirstObservedAt time.Time `json:"first_observed_at"`
	LastObservedAt  time.Time `json:"last_observed_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
