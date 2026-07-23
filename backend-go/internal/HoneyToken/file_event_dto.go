package honeytoken

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CreateFileEventRequest contains event information collected by a trusted
// filesystem watcher, agent or internal security service.
type CreateFileEventRequest struct {
	DepartmentID     *string `json:"department_id" binding:"omitempty,uuid"`
	MonitoringRuleID *string `json:"monitoring_rule_id" binding:"omitempty,uuid"`

	ProtectedFileID *string `json:"protected_file_id" binding:"omitempty,uuid"`
	HoneytokenID    *string `json:"honeytoken_id" binding:"omitempty,uuid"`
	CanaryFileID    *string `json:"canary_file_id" binding:"omitempty,uuid"`

	SourceType      string  `json:"source_type" binding:"required,oneof=PROTECTED_FILE HONEYTOKEN CANARY_FILE UNMANAGED_FILE"`
	EventType       string  `json:"event_type" binding:"required,oneof=CREATED OPENED READ COPIED MOVED RENAMED MODIFIED ENCRYPTED DELETED EXTENSION_CHANGED PERMISSION_CHANGED HASH_CHANGED MULTIPLE_FILE_CHANGES CUSTOM"`
	EventSource     string  `json:"event_source" binding:"required,oneof=WINDOWS_WATCHER LINUX_INOTIFY MACOS_FSEVENTS API AGENT MANUAL SYSTEM"`
	DetectionMethod *string `json:"detection_method" binding:"omitempty,oneof=RULE_BASED SIGNATURE_BASED BEHAVIOUR_BASED AI_BASED HYBRID"`

	FileName         string  `json:"file_name" binding:"required,min=1,max=255"`
	FilePath         string  `json:"file_path" binding:"required,min=1,max=4096"`
	PreviousFilePath *string `json:"previous_file_path" binding:"omitempty,max=4096"`
	FileExtension    *string `json:"file_extension" binding:"omitempty,max=50"`
	MimeType         *string `json:"mime_type" binding:"omitempty,max=255"`

	FileSizeBefore *int64 `json:"file_size_before" binding:"omitempty,min=0"`
	FileSizeAfter  *int64 `json:"file_size_after" binding:"omitempty,min=0"`

	PreviousHash  *string `json:"previous_hash" binding:"omitempty,max=128"`
	CurrentHash   *string `json:"current_hash" binding:"omitempty,max=128"`
	HashAlgorithm *string `json:"hash_algorithm" binding:"omitempty,oneof=SHA256 SHA384 SHA512"`

	ProcessID         *int64  `json:"process_id" binding:"omitempty,min=0"`
	ProcessName       *string `json:"process_name" binding:"omitempty,max=255"`
	ExecutablePath    *string `json:"executable_path" binding:"omitempty,max=4096"`
	ParentProcessID   *int64  `json:"parent_process_id" binding:"omitempty,min=0"`
	ParentProcessName *string `json:"parent_process_name" binding:"omitempty,max=255"`
	CommandLine       *string `json:"command_line" binding:"omitempty,max=8192"`
	ProcessHash       *string `json:"process_hash" binding:"omitempty,max=128"`

	SystemUsername   *string `json:"system_username" binding:"omitempty,max=255"`
	DeviceName       *string `json:"device_name" binding:"omitempty,max=255"`
	DeviceIdentifier *string `json:"device_identifier" binding:"omitempty,max=255"`
	MACAddress       *string `json:"mac_address" binding:"omitempty,max=50"`

	RawEvent json.RawMessage `json:"raw_event"`
	Metadata json.RawMessage `json:"metadata"`

	OccurredAt string `json:"occurred_at" binding:"required"`
}

// CreateFileEventResponse confirms durable event registration.
type CreateFileEventResponse struct {
	ID            uuid.UUID `json:"id"`
	EventSequence int64     `json:"event_sequence"`
	EventCode     string    `json:"event_code"`

	SourceType string `json:"source_type"`
	EventType  string `json:"event_type"`
	FileName   string `json:"file_name"`

	Severity     string `json:"severity"`
	ThreatScore  int    `json:"threat_score"`
	IsSuspicious bool   `json:"is_suspicious"`
	Status       string `json:"status"`

	OccurredAt time.Time `json:"occurred_at"`
	ReceivedAt time.Time `json:"received_at"`
}

// GetFileEventResponse contains safe forensic metadata. Internal paths,
// command lines, network addresses and raw watcher payloads are excluded.
type GetFileEventResponse struct {
	ID            uuid.UUID `json:"id"`
	EventSequence int64     `json:"event_sequence"`
	EventCode     string    `json:"event_code"`

	OrganizationID   uuid.UUID  `json:"organization_id"`
	DepartmentID     *uuid.UUID `json:"department_id,omitempty"`
	MonitoringRuleID *uuid.UUID `json:"monitoring_rule_id,omitempty"`

	ProtectedFileID *uuid.UUID `json:"protected_file_id,omitempty"`
	HoneytokenID    *uuid.UUID `json:"honeytoken_id,omitempty"`
	CanaryFileID    *uuid.UUID `json:"canary_file_id,omitempty"`

	SourceType      string `json:"source_type"`
	EventType       string `json:"event_type"`
	EventSource     string `json:"event_source"`
	DetectionMethod string `json:"detection_method"`

	FileName      string  `json:"file_name"`
	FileExtension *string `json:"file_extension,omitempty"`
	MimeType      *string `json:"mime_type,omitempty"`

	FileSizeBefore *int64 `json:"file_size_before,omitempty"`
	FileSizeAfter  *int64 `json:"file_size_after,omitempty"`

	PreviousHash  *string `json:"previous_hash,omitempty"`
	CurrentHash   *string `json:"current_hash,omitempty"`
	HashAlgorithm string  `json:"hash_algorithm"`

	ProcessID         *int64  `json:"process_id,omitempty"`
	ProcessName       *string `json:"process_name,omitempty"`
	ParentProcessID   *int64  `json:"parent_process_id,omitempty"`
	ParentProcessName *string `json:"parent_process_name,omitempty"`
	ProcessHash       *string `json:"process_hash,omitempty"`

	SystemUsername   *string `json:"system_username,omitempty"`
	DeviceName       *string `json:"device_name,omitempty"`
	DeviceIdentifier *string `json:"device_identifier,omitempty"`

	Severity     string `json:"severity"`
	ThreatScore  int    `json:"threat_score"`
	IsSuspicious bool   `json:"is_suspicious"`
	Status       string `json:"status"`

	EvidenceHash *string         `json:"evidence_hash,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`

	OccurredAt  time.Time  `json:"occurred_at"`
	ReceivedAt  time.Time  `json:"received_at"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// ListFileEventsRequest contains tenant-isolated event filters.
type ListFileEventsRequest struct {
	DepartmentID *string `form:"department_id" binding:"omitempty,uuid"`

	SourceType string `form:"source_type" binding:"omitempty,oneof=PROTECTED_FILE HONEYTOKEN CANARY_FILE UNMANAGED_FILE"`
	EventType  string `form:"event_type" binding:"omitempty,oneof=CREATED OPENED READ COPIED MOVED RENAMED MODIFIED ENCRYPTED DELETED EXTENSION_CHANGED PERMISSION_CHANGED HASH_CHANGED MULTIPLE_FILE_CHANGES CUSTOM"`
	Severity   string `form:"severity" binding:"omitempty,oneof=LOW MEDIUM HIGH CRITICAL"`
	Status     string `form:"status" binding:"omitempty,oneof=RECEIVED QUEUED PROCESSING PROCESSED FAILED IGNORED"`

	IsSuspicious *bool `form:"is_suspicious"`

	From *string `form:"from"`
	To   *string `form:"to"`

	Page     int `form:"page" binding:"omitempty,min=1"`
	PageSize int `form:"page_size" binding:"omitempty,min=1,max=100"`
}

// ListFileEventsResponse contains a paginated forensic event collection.
type ListFileEventsResponse struct {
	Items      []GetFileEventResponse `json:"items"`
	Total      int64                  `json:"total"`
	Page       int                    `json:"page"`
	PageSize   int                    `json:"page_size"`
	TotalPages int                    `json:"total_pages"`
}
