package user

import (
	"time"

	"github.com/google/uuid"
)

type CreateUserRequest struct {
	Username      string    `json:"username" binding:"required,min=3,max=50"`
	OfficialEmail string    `json:"official_email" binding:"required,email"`
	Password      string    `json:"password" binding:"required,min=8"`
	UserType      string    `json:"user_type" binding:"required"`
	FirstName     string    `json:"first_name" binding:"required"`
	MiddleName    *string   `json:"middle_name"`
	LastName      *string   `json:"last_name"`
	DisplayName   *string   `json:"display_name"`
	Designation   *string   `json:"designation"`
	OfficialPhone *string   `json:"official_phone"`
	RoleID        uuid.UUID `json:"role_id" binding:"required"`
	EmployeeCode  *string   `json:"employee_code"`
}

type CreateUserResponse struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Username       string    `json:"username"`
	OfficialEmail  string    `json:"official_email"`
	DisplayName    string    `json:"display_name"`
	AccountStatus  string    `json:"account_status"`
	RoleID         uuid.UUID `json:"role_id"`
}

type ListUsersRequest struct {
	Page          int    `form:"page"`
	Limit         int    `form:"limit"`
	Search        string `form:"search"`
	AccountStatus string `form:"account_status"`
	UserType      string `form:"user_type"`
	SortBy        string `form:"sort_by"`
	SortOrder     string `form:"sort_order"`
}

type UserListItem struct {
	ID            uuid.UUID `json:"id"`
	Username      string    `json:"username"`
	OfficialEmail string    `json:"official_email"`
	DisplayName   string    `json:"display_name"`
	Designation   *string   `json:"designation,omitempty"`
	AccountStatus string    `json:"account_status"`
	UserType      string    `json:"user_type"`
	Role          string    `json:"role"`
	CreatedAt     time.Time `json:"created_at"`
}

type ListUsersResponse struct {
	Users      []UserListItem `json:"users"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	Limit      int            `json:"limit"`
	TotalPages int            `json:"total_pages"`
}

type GetUserResponse struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	Username       string     `json:"username"`
	OfficialEmail  string     `json:"official_email"`
	UserType       string     `json:"user_type"`
	AccountStatus  string     `json:"account_status"`
	EmployeeCode   *string    `json:"employee_code,omitempty"`
	FirstName      string     `json:"first_name"`
	MiddleName     *string    `json:"middle_name,omitempty"`
	LastName       *string    `json:"last_name,omitempty"`
	DisplayName    string     `json:"display_name"`
	Designation    *string    `json:"designation,omitempty"`
	OfficialPhone  *string    `json:"official_phone,omitempty"`
	RoleID         *uuid.UUID `json:"role_id,omitempty"`
	RoleCode       *string    `json:"role_code,omitempty"`
	RoleName       *string    `json:"role_name,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type UpdateUserRequest struct {
	OfficialEmail *string `json:"official_email"`
	EmployeeCode  *string `json:"employee_code"`
	FirstName     *string `json:"first_name"`
	MiddleName    *string `json:"middle_name"`
	LastName      *string `json:"last_name"`
	DisplayName   *string `json:"display_name"`
	Designation   *string `json:"designation"`
	OfficialPhone *string `json:"official_phone"`
}

// ChangeAccountStatusRequest intentionally supports reversible lifecycle
// control instead of deleting user accounts and their investigation history.
type ChangeAccountStatusRequest struct {
	Status string `json:"status" binding:"required,oneof=ACTIVE BLOCKED"`
	Reason string `json:"reason" binding:"omitempty,max=500"`
}
