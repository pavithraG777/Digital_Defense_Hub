package honeytoken

// RegisterProtectedFileRequest represents a request to register
// a file into the Digital Defense Hub Protected File Vault.
type RegisterProtectedFileRequest struct {
	OrganizationID string `json:"organization_id" binding:"required,uuid"`
	DepartmentID   string `json:"department_id,omitempty"`
	OwnerUserID    string `json:"owner_user_id" binding:"required,uuid"`

	OriginalFilePath string `json:"original_file_path" binding:"required"`
	Category         string `json:"category" binding:"required"`
	Sensitivity      string `json:"sensitivity" binding:"required"`
	Classification   string `json:"classification" binding:"required"`

	RetentionPolicy         string `json:"retention_policy"`
	OriginalRetentionPolicy string `json:"original_retention_policy"`

	EnableMonitoring bool `json:"enable_monitoring"`
	EnableHoneytoken bool `json:"enable_honeytoken"`
	EnableCanary     bool `json:"enable_canary"`
}

// RegisterProtectedFileResponse represents the response after
// successfully registering a protected file.
type RegisterProtectedFileResponse struct {
	ProtectedFileID string `json:"protected_file_id"`

	OriginalFileName  string `json:"original_file_name"`
	ProtectedFileName string `json:"protected_file_name"`

	Status string `json:"status"`

	MonitoringEnabled bool `json:"monitoring_enabled"`
	HoneytokenEnabled bool `json:"honeytoken_enabled"`
	CanaryEnabled     bool `json:"canary_enabled"`
}

// GetProtectedFileResponse represents protected file details.
type GetProtectedFileResponse struct {
	ID string `json:"id"`

	OrganizationID string `json:"organization_id"`
	DepartmentID   string `json:"department_id,omitempty"`
	OwnerUserID    string `json:"owner_user_id"`

	OriginalFileName  string `json:"original_file_name"`
	ProtectedFileName string `json:"protected_file_name"`

	Category       string `json:"category"`
	Sensitivity    string `json:"sensitivity"`
	Classification string `json:"classification"`

	FileSizeBytes int64  `json:"file_size_bytes"`
	MimeType      string `json:"mime_type"`

	Status string `json:"status"`

	MonitoringEnabled bool `json:"monitoring_enabled"`
	HoneytokenEnabled bool `json:"honeytoken_enabled"`
	CanaryEnabled     bool `json:"canary_enabled"`

	CreatedAt string `json:"created_at"`
}

// RestoreProtectedFileRequest represents an authorized request to
// restore an original file from its encrypted .ddh package.
//
// The client must not provide the protected package path, encryption
// key ID, original filename or SHA-256 hash. Those trusted values
// will be loaded from the database.
type RestoreProtectedFileRequest struct {
	RestoreReason string `json:"restore_reason" binding:"required,min=3,max=500"`
}

// StartOwnerProtectedFileRestoreResponse contains the OTP challenge
// details that allow the file owner to verify before restoration.
type StartOwnerProtectedFileRestoreResponse struct {
	MFAChallengeID   string `json:"mfa_challenge_id"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

// RestoreProtectedFileOwnerRequest represents an owner-initiated restore
// request that includes a verified email OTP challenge.
type RestoreProtectedFileOwnerRequest struct {
	RestoreReason  string `json:"restore_reason" binding:"required,min=3,max=500"`
	MFAChallengeID string `json:"mfa_challenge_id" binding:"required,uuid"`
	EmailCode      string `json:"email_code" binding:"required,len=6,numeric"`
	Password       string `json:"password" binding:"required,min=8,max=128"`
	DeviceID       string `json:"device_id" binding:"required,min=8,max=255"`
	Download       bool   `json:"download"`
}

// RestoreProtectedFileResponse contains safe information about a
// successfully restored protected file.
type RestoreProtectedFileResponse struct {
	ProtectedFileID string `json:"protected_file_id"`

	RestoredFileName string `json:"restored_file_name"`
	FileSizeBytes    int64  `json:"file_size_bytes"`

	IntegrityVerified bool   `json:"integrity_verified"`
	RestoredAt        string `json:"restored_at"`
}
