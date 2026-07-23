package honeytoken

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// FileEvent represents an immutable filesystem or monitored-resource event
// collected for threat analysis and digital forensic investigation.
type FileEvent struct {
	ID            uuid.UUID `json:"id" db:"id"`
	EventSequence int64     `json:"event_sequence" db:"event_sequence"`
	EventCode     string    `json:"event_code" db:"event_code"`

	// EventFingerprint is used internally for duplicate-event prevention.
	EventFingerprint string `json:"-" db:"event_fingerprint"`

	OrganizationID   uuid.UUID  `json:"organization_id" db:"organization_id"`
	DepartmentID     *uuid.UUID `json:"department_id,omitempty" db:"department_id"`
	MonitoringRuleID *uuid.UUID `json:"monitoring_rule_id,omitempty" db:"monitoring_rule_id"`

	ProtectedFileID *uuid.UUID `json:"protected_file_id,omitempty" db:"protected_file_id"`
	HoneytokenID    *uuid.UUID `json:"honeytoken_id,omitempty" db:"honeytoken_id"`
	CanaryFileID    *uuid.UUID `json:"canary_file_id,omitempty" db:"canary_file_id"`

	SourceType      string `json:"source_type" db:"source_type"`
	EventType       string `json:"event_type" db:"event_type"`
	EventSource     string `json:"event_source" db:"event_source"`
	DetectionMethod string `json:"detection_method" db:"detection_method"`

	FileName         string  `json:"file_name" db:"file_name"`
	FilePath         string  `json:"-" db:"file_path"`
	PreviousFilePath *string `json:"-" db:"previous_file_path"`
	FileExtension    *string `json:"file_extension,omitempty" db:"file_extension"`
	MimeType         *string `json:"mime_type,omitempty" db:"mime_type"`

	FileSizeBefore *int64 `json:"file_size_before,omitempty" db:"file_size_before"`
	FileSizeAfter  *int64 `json:"file_size_after,omitempty" db:"file_size_after"`

	PreviousHash  *string `json:"previous_hash,omitempty" db:"previous_hash"`
	CurrentHash   *string `json:"current_hash,omitempty" db:"current_hash"`
	HashAlgorithm string  `json:"hash_algorithm" db:"hash_algorithm"`

	ProcessID         *int64  `json:"process_id,omitempty" db:"process_id"`
	ProcessName       *string `json:"process_name,omitempty" db:"process_name"`
	ExecutablePath    *string `json:"-" db:"executable_path"`
	ParentProcessID   *int64  `json:"parent_process_id,omitempty" db:"parent_process_id"`
	ParentProcessName *string `json:"parent_process_name,omitempty" db:"parent_process_name"`
	CommandLine       *string `json:"-" db:"command_line"`
	ProcessHash       *string `json:"process_hash,omitempty" db:"process_hash"`

	SystemUsername    *string    `json:"system_username,omitempty" db:"system_username"`
	ApplicationUserID *uuid.UUID `json:"application_user_id,omitempty" db:"application_user_id"`

	DeviceName       *string `json:"device_name,omitempty" db:"device_name"`
	DeviceIdentifier *string `json:"device_identifier,omitempty" db:"device_identifier"`
	IPAddress        *string `json:"-" db:"ip_address"`
	MACAddress       *string `json:"-" db:"mac_address"`

	Severity     string `json:"severity" db:"severity"`
	ThreatScore  int    `json:"threat_score" db:"threat_score"`
	IsSuspicious bool   `json:"is_suspicious" db:"is_suspicious"`

	Status          string  `json:"status" db:"status"`
	ProcessingError *string `json:"-" db:"processing_error"`

	EvidenceCopyPath *string `json:"-" db:"evidence_copy_path"`
	EvidenceHash     *string `json:"evidence_hash,omitempty" db:"evidence_hash"`

	RawEvent json.RawMessage `json:"-" db:"raw_event"`
	Metadata json.RawMessage `json:"metadata,omitempty" db:"metadata"`

	OccurredAt  time.Time  `json:"occurred_at" db:"occurred_at"`
	ReceivedAt  time.Time  `json:"received_at" db:"received_at"`
	ProcessedAt *time.Time `json:"processed_at,omitempty" db:"processed_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}
