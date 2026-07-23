package honeytoken

import (
	"time"

	"github.com/google/uuid"
)

// CanaryFile represents a monitored decoy file deployed inside an
// organization to detect unauthorized access and file tampering.
type CanaryFile struct {
	ID uuid.UUID `json:"id" db:"id"`

	OrganizationID uuid.UUID  `json:"organization_id" db:"organization_id"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty" db:"department_id"`
	PolicyID       *uuid.UUID `json:"policy_id,omitempty" db:"policy_id"`

	CanaryCode string `json:"canary_code" db:"canary_code"`
	FileName   string `json:"file_name" db:"file_name"`
	FilePath   string `json:"-" db:"file_path"`

	FileExtension *string `json:"file_extension,omitempty" db:"file_extension"`
	MimeType      *string `json:"mime_type,omitempty" db:"mime_type"`
	CanaryType    string  `json:"canary_type" db:"canary_type"`
	Description   *string `json:"description,omitempty" db:"description"`

	OriginalFileHash string `json:"original_file_hash" db:"original_file_hash"`
	HashAlgorithm    string `json:"hash_algorithm" db:"hash_algorithm"`
	FileSizeBytes    *int64 `json:"file_size_bytes,omitempty" db:"file_size_bytes"`

	TrackingIdentifier string `json:"-" db:"tracking_identifier"`

	ContainsHoneytoken bool       `json:"contains_honeytoken" db:"contains_honeytoken"`
	HoneytokenID       *uuid.UUID `json:"honeytoken_id,omitempty" db:"honeytoken_id"`

	DeployedDeviceName       *string `json:"deployed_device_name,omitempty" db:"deployed_device_name"`
	DeployedDeviceIdentifier *string `json:"deployed_device_identifier,omitempty" db:"deployed_device_identifier"`

	OwnerUserID *uuid.UUID `json:"owner_user_id,omitempty" db:"owner_user_id"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" db:"created_by"`

	AccessCount     int        `json:"access_count" db:"access_count"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty" db:"last_triggered_at"`
	DeployedAt      *time.Time `json:"deployed_at,omitempty" db:"deployed_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty" db:"expires_at"`

	Status string `json:"status" db:"status"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}
