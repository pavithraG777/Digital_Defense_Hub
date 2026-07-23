package honeytoken

import (
	"time"

	"github.com/google/uuid"
)

// CreateCanaryFileRequest contains administrator-controlled canary
// configuration. Organization and creator IDs are obtained from JWT.
type CreateCanaryFileRequest struct {
	DepartmentID *string `json:"department_id" binding:"omitempty,uuid"`
	PolicyID     *string `json:"policy_id" binding:"omitempty,uuid"`
	OwnerUserID  *string `json:"owner_user_id" binding:"omitempty,uuid"`

	FileName    string  `json:"file_name" binding:"required,min=1,max=255"`
	CanaryType  string  `json:"canary_type" binding:"required,oneof=DOCUMENT SPREADSHEET PDF IMAGE ARCHIVE DATABASE_BACKUP CONFIGURATION SOURCE_CODE CREDENTIAL_FILE CUSTOM"`
	Description *string `json:"description" binding:"omitempty,max=2000"`

	ContainsHoneytoken bool    `json:"contains_honeytoken"`
	HoneytokenID       *string `json:"honeytoken_id" binding:"omitempty,uuid"`

	ExpiresAt *string `json:"expires_at" binding:"omitempty"`
}

// CreateCanaryFileResponse returns safe metadata about the generated file.
type CreateCanaryFileResponse struct {
	ID                 uuid.UUID  `json:"id"`
	CanaryCode         string     `json:"canary_code"`
	FileName           string     `json:"file_name"`
	FileExtension      *string    `json:"file_extension,omitempty"`
	MimeType           *string    `json:"mime_type,omitempty"`
	CanaryType         string     `json:"canary_type"`
	HashAlgorithm      string     `json:"hash_algorithm"`
	FileSizeBytes      *int64     `json:"file_size_bytes,omitempty"`
	ContainsHoneytoken bool       `json:"contains_honeytoken"`
	HoneytokenID       *uuid.UUID `json:"honeytoken_id,omitempty"`
	Status             string     `json:"status"`
	CreatedAt          time.Time  `json:"created_at"`
}

// GetCanaryFileResponse excludes the internal tracking identifier and
// physical storage path from general API responses.
type GetCanaryFileResponse struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`
	PolicyID       *uuid.UUID `json:"policy_id,omitempty"`

	CanaryCode    string  `json:"canary_code"`
	FileName      string  `json:"file_name"`
	FileExtension *string `json:"file_extension,omitempty"`
	MimeType      *string `json:"mime_type,omitempty"`
	CanaryType    string  `json:"canary_type"`
	Description   *string `json:"description,omitempty"`

	OriginalFileHash string `json:"original_file_hash"`
	HashAlgorithm    string `json:"hash_algorithm"`
	FileSizeBytes    *int64 `json:"file_size_bytes,omitempty"`

	ContainsHoneytoken bool       `json:"contains_honeytoken"`
	HoneytokenID       *uuid.UUID `json:"honeytoken_id,omitempty"`

	DeployedDeviceName       *string    `json:"deployed_device_name,omitempty"`
	DeployedDeviceIdentifier *string    `json:"deployed_device_identifier,omitempty"`
	OwnerUserID              *uuid.UUID `json:"owner_user_id,omitempty"`

	AccessCount     int        `json:"access_count"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	DeployedAt      *time.Time `json:"deployed_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`

	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListCanaryFilesRequest contains tenant-isolated list filters.
type ListCanaryFilesRequest struct {
	DepartmentID *string `form:"department_id" binding:"omitempty,uuid"`
	CanaryType   string  `form:"canary_type" binding:"omitempty,oneof=DOCUMENT SPREADSHEET PDF IMAGE ARCHIVE DATABASE_BACKUP CONFIGURATION SOURCE_CODE CREDENTIAL_FILE CUSTOM"`
	Status       string  `form:"status" binding:"omitempty,oneof=DRAFT DEPLOYED ACTIVE TRIGGERED TAMPERED MISSING INACTIVE EXPIRED ARCHIVED"`
	Page         int     `form:"page" binding:"omitempty,min=1"`
	PageSize     int     `form:"page_size" binding:"omitempty,min=1,max=100"`
}

// ListCanaryFilesResponse contains paginated canary metadata.
type ListCanaryFilesResponse struct {
	Items      []GetCanaryFileResponse `json:"items"`
	Total      int64                   `json:"total"`
	Page       int                     `json:"page"`
	PageSize   int                     `json:"page_size"`
	TotalPages int                     `json:"total_pages"`
}

// DeployCanaryFileRequest selects the protected destination and device.
type DeployCanaryFileRequest struct {
	DeploymentDirectory string  `json:"deployment_directory" binding:"required,min=1,max=4096"`
	DeviceName          *string `json:"device_name" binding:"omitempty,max=255"`
	DeviceIdentifier    *string `json:"device_identifier" binding:"omitempty,max=255"`
}

// DeployCanaryFileResponse confirms successful physical deployment.
type DeployCanaryFileResponse struct {
	ID                       uuid.UUID `json:"id"`
	FileName                 string    `json:"file_name"`
	DeployedDeviceName       *string   `json:"deployed_device_name,omitempty"`
	DeployedDeviceIdentifier *string   `json:"deployed_device_identifier,omitempty"`
	Status                   string    `json:"status"`
	DeployedAt               time.Time `json:"deployed_at"`
}
