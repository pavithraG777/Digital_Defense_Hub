package honeytoken

import (
	"time"

	"github.com/google/uuid"
)

// Honeytoken represents one organization-owned decoy credential,
// token, record, URL or document value used for threat detection.
type Honeytoken struct {
	ID uuid.UUID `json:"id" db:"id"`

	OrganizationID uuid.UUID  `json:"organization_id" db:"organization_id"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty" db:"department_id"`
	PolicyID       *uuid.UUID `json:"policy_id,omitempty" db:"policy_id"`

	HoneytokenCode string `json:"honeytoken_code" db:"honeytoken_code"`
	HoneytokenName string `json:"honeytoken_name" db:"honeytoken_name"`
	HoneytokenType string `json:"honeytoken_type" db:"honeytoken_type"`

	Description *string `json:"description,omitempty" db:"description"`

	DecoyUsername *string `json:"decoy_username,omitempty" db:"decoy_username"`
	DecoyEmail    *string `json:"decoy_email,omitempty" db:"decoy_email"`

	// DecoyValueEncrypted contains protected decoy material.
	// It must never be exposed through JSON responses.
	DecoyValueEncrypted *string `json:"-" db:"decoy_value_encrypted"`

	// DecoyValueHash is used for validation and matching.
	// It must not be exposed through general API responses.
	DecoyValueHash *string `json:"-" db:"decoy_value_hash"`

	// ValuePrefix contains only a safe non-secret preview.
	ValuePrefix *string `json:"value_prefix,omitempty" db:"value_prefix"`

	TargetSystem       *string `json:"target_system,omitempty" db:"target_system"`
	DeploymentLocation *string `json:"-" db:"deployment_location"`

	Classification string `json:"classification" db:"classification"`
	AccessCount    int    `json:"access_count" db:"access_count"`

	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty" db:"last_triggered_at"`

	OwnerUserID *uuid.UUID `json:"owner_user_id,omitempty" db:"owner_user_id"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" db:"created_by"`

	DeployedAt *time.Time `json:"deployed_at,omitempty" db:"deployed_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`

	Status string `json:"status" db:"status"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}
