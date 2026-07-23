package honeytoken

import (
	"time"

	"github.com/google/uuid"
)

// ProtectedFile represents an original file secured inside the
// Digital Defense Hub protected file vault.
type ProtectedFile struct {
	ID uuid.UUID `json:"id" db:"id"`

	OrganizationID uuid.UUID  `json:"organization_id" db:"organization_id"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty" db:"department_id"`
	OwnerUserID    uuid.UUID  `json:"owner_user_id" db:"owner_user_id"`

	OriginalFileName  string `json:"original_file_name" db:"original_file_name"`
	OriginalExtension string `json:"original_extension" db:"original_extension"`
	OriginalFilePath  string `json:"original_file_path" db:"original_file_path"`

	ProtectedFileName string `json:"protected_file_name" db:"protected_file_name"`
	ProtectedFilePath string `json:"protected_file_path" db:"protected_file_path"`

	MetadataFileName string `json:"metadata_file_name" db:"metadata_file_name"`
	MetadataFilePath string `json:"metadata_file_path" db:"metadata_file_path"`

	FileSizeBytes int64  `json:"file_size_bytes" db:"file_size_bytes"`
	MimeType      string `json:"mime_type" db:"mime_type"`
	SHA256Hash    string `json:"sha256_hash" db:"sha256_hash"`

	EncryptionAlgorithm string `json:"encryption_algorithm" db:"encryption_algorithm"`
	EncryptionKeyID     string `json:"encryption_key_id" db:"encryption_key_id"`

	Category       string `json:"category" db:"category"`
	Sensitivity    string `json:"sensitivity" db:"sensitivity"`
	Classification string `json:"classification" db:"classification"`

	RetentionPolicy string     `json:"retention_policy" db:"retention_policy"`
	RetentionUntil  *time.Time `json:"retention_until,omitempty" db:"retention_until"`

	MonitoringEnabled bool `json:"monitoring_enabled" db:"monitoring_enabled"`
	HoneytokenEnabled bool `json:"honeytoken_enabled" db:"honeytoken_enabled"`
	CanaryEnabled     bool `json:"canary_enabled" db:"canary_enabled"`

	Status string `json:"status" db:"status"`

	ProtectedAt *time.Time `json:"protected_at,omitempty" db:"protected_at"`
	ArchivedAt  *time.Time `json:"archived_at,omitempty" db:"archived_at"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}
