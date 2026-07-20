package permission

import (
	"time"

	"github.com/google/uuid"
)

type Permission struct {
	ID               uuid.UUID `json:"id"`
	PermissionCode   string    `json:"permission_code"`
	PermissionName   string    `json:"permission_name"`
	ModuleName       string    `json:"module_name"`
	ActionName       string    `json:"action_name"`
	Description      *string   `json:"description,omitempty"`
	RiskLevel        string    `json:"risk_level"`
	RequiresApproval bool      `json:"requires_approval"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}
