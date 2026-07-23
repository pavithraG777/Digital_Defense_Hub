package honeytoken

// CreateHoneytokenRequest contains safe user-configurable metadata.
//
// OrganizationID and CreatedBy are intentionally excluded because
// they must come from the authenticated JWT context.
type CreateHoneytokenRequest struct {
	DepartmentID string `json:"department_id,omitempty" binding:"omitempty,uuid"`
	PolicyID     string `json:"policy_id,omitempty" binding:"omitempty,uuid"`
	OwnerUserID  string `json:"owner_user_id,omitempty" binding:"omitempty,uuid"`

	HoneytokenName string `json:"honeytoken_name" binding:"required,min=3,max=100"`
	HoneytokenType string `json:"honeytoken_type" binding:"required"`

	Description string `json:"description,omitempty" binding:"omitempty,max=1000"`

	DecoyUsername string `json:"decoy_username,omitempty" binding:"omitempty,max=100"`
	DecoyEmail    string `json:"decoy_email,omitempty" binding:"omitempty,email,max=255"`

	TargetSystem string `json:"target_system,omitempty" binding:"omitempty,max=100"`

	Classification string `json:"classification" binding:"required"`

	// ExpiresAt must use RFC3339 format when supplied.
	// Example: 2027-07-23T18:30:00+05:30
	ExpiresAt string `json:"expires_at,omitempty"`
}

// CreateHoneytokenResponse returns generated decoy material exactly
// once so an authorized user can deploy it.
//
// GeneratedValue must not be stored in frontend logs or browser storage.
type CreateHoneytokenResponse struct {
	ID string `json:"id"`

	HoneytokenCode string `json:"honeytoken_code"`
	HoneytokenName string `json:"honeytoken_name"`
	HoneytokenType string `json:"honeytoken_type"`

	GeneratedValue string `json:"generated_value"`
	ValuePrefix    string `json:"value_prefix,omitempty"`

	Classification string `json:"classification"`
	Status         string `json:"status"`

	ExpiresAt string `json:"expires_at,omitempty"`
	CreatedAt string `json:"created_at"`
}

// GetHoneytokenResponse contains safe metadata for an existing
// honeytoken. Encrypted values and hashes are never returned.
type GetHoneytokenResponse struct {
	ID string `json:"id"`

	OrganizationID string `json:"organization_id"`
	DepartmentID   string `json:"department_id,omitempty"`
	PolicyID       string `json:"policy_id,omitempty"`

	HoneytokenCode string `json:"honeytoken_code"`
	HoneytokenName string `json:"honeytoken_name"`
	HoneytokenType string `json:"honeytoken_type"`

	Description string `json:"description,omitempty"`

	DecoyUsername string `json:"decoy_username,omitempty"`
	DecoyEmail    string `json:"decoy_email,omitempty"`
	ValuePrefix   string `json:"value_prefix,omitempty"`

	TargetSystem string `json:"target_system,omitempty"`

	Classification string `json:"classification"`
	AccessCount    int    `json:"access_count"`

	OwnerUserID string `json:"owner_user_id,omitempty"`
	CreatedBy   string `json:"created_by,omitempty"`

	DeploymentConfigured bool `json:"deployment_configured"`

	LastTriggeredAt string `json:"last_triggered_at,omitempty"`
	DeployedAt      string `json:"deployed_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`

	Status string `json:"status"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ListHoneytokensRequest contains supported query parameters.
type ListHoneytokensRequest struct {
	Page  int `form:"page" binding:"omitempty,min=1"`
	Limit int `form:"limit" binding:"omitempty,min=1,max=100"`

	Search         string `form:"search" binding:"omitempty,max=100"`
	HoneytokenType string `form:"honeytoken_type"`
	Classification string `form:"classification"`
	Status         string `form:"status"`
	DepartmentID   string `form:"department_id" binding:"omitempty,uuid"`
}

// ListHoneytokensResponse contains paginated safe honeytoken metadata.
type ListHoneytokensResponse struct {
	Honeytokens []GetHoneytokenResponse `json:"honeytokens"`

	Total      int `json:"total"`
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	TotalPages int `json:"total_pages"`
}

// DeployHoneytokenRequest activates a generated honeytoken at an
// authorized deployment location.
type DeployHoneytokenRequest struct {
	DeploymentLocation string `json:"deployment_location" binding:"required,min=1,max=4096"`
	TargetSystem       string `json:"target_system,omitempty" binding:"omitempty,max=100"`
}

// DeployHoneytokenResponse confirms successful deployment.
type DeployHoneytokenResponse struct {
	ID string `json:"id"`

	HoneytokenCode string `json:"honeytoken_code"`
	HoneytokenName string `json:"honeytoken_name"`

	TargetSystem string `json:"target_system,omitempty"`

	DeploymentConfigured bool   `json:"deployment_configured"`
	Status               string `json:"status"`
	DeployedAt           string `json:"deployed_at"`
}

// ValidateHoneytokenRequest contains a value observed by a monitoring
// agent or detection service.
type ValidateHoneytokenRequest struct {
	ObservedValue string `json:"observed_value" binding:"required,min=1,max=8192"`
}

// ValidateHoneytokenResponse reports whether an active honeytoken
// was triggered without returning the protected decoy value.
type ValidateHoneytokenResponse struct {
	ID string `json:"id"`

	HoneytokenCode string `json:"honeytoken_code"`

	Valid     bool `json:"valid"`
	Triggered bool `json:"triggered"`

	Status      string `json:"status"`
	AccessCount int    `json:"access_count"`

	TriggeredAt string `json:"triggered_at,omitempty"`
}
