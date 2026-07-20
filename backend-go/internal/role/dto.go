package role

import "github.com/google/uuid"

type CreateRoleRequest struct {
	RoleCode      string     `json:"role_code" binding:"required"`
	RoleName      string     `json:"role_name" binding:"required"`
	Description   *string    `json:"description"`
	RoleScope     string     `json:"role_scope"`
	DepartmentID  *uuid.UUID `json:"department_id"`
	PriorityLevel *int       `json:"priority_level"`
}

type CreateRoleResponse struct {
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
}

type ListRolesRequest struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Search   string `form:"search"`
	Status   string `form:"status"`
}

type RoleListItem struct {
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
}

type ListRolesResponse struct {
	Roles      []RoleListItem `json:"roles"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalCount int64          `json:"total_count"`
	TotalPages int            `json:"total_pages"`
}

type GetRoleResponse struct {
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
}

type UpdateRoleRequest struct {
	RoleName      *string    `json:"role_name"`
	Description   *string    `json:"description"`
	RoleScope     *string    `json:"role_scope"`
	DepartmentID  *uuid.UUID `json:"department_id"`
	PriorityLevel *int       `json:"priority_level"`
	Status        *string    `json:"status"`
}
