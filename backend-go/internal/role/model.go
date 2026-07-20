package role

import (
	"time"

	"github.com/google/uuid"
)

type Role struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	RoleCode       string     `json:"role_code"`
	RoleName       string     `json:"role_name"`
	Description    *string    `json:"description,omitempty"`
	RoleScope      string     `json:"role_scope"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`
	IsSystemRole   bool       `json:"is_system_role"`
	PriorityLevel  int        `json:"priority_level"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}
