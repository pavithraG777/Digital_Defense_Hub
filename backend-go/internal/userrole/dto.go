package userrole

import (
	"time"

	"github.com/google/uuid"
)

type AssignRolesRequest struct {
	RoleIDs   []uuid.UUID `json:"role_ids" binding:"required,min=1"`
	ExpiresAt *time.Time  `json:"expires_at"`
}

type AssignedRoleItem struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	RoleID    uuid.UUID  `json:"role_id"`
	GrantedBy *uuid.UUID `json:"granted_by,omitempty"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	IsActive  bool       `json:"is_active"`
}

type AssignRolesResponse struct {
	UserID        uuid.UUID          `json:"user_id"`
	AssignedRoles []AssignedRoleItem `json:"assigned_roles"`
	AssignedCount int                `json:"assigned_count"`
	SkippedCount  int                `json:"skipped_count"`
}

type UserRoleListItem struct {
	MappingID   uuid.UUID  `json:"mapping_id"`
	RoleID      uuid.UUID  `json:"role_id"`
	RoleCode    string     `json:"role_code"`
	RoleName    string     `json:"role_name"`
	Description *string    `json:"description,omitempty"`
	GrantedBy   *uuid.UUID `json:"granted_by,omitempty"`
	GrantedAt   time.Time  `json:"granted_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	IsActive    bool       `json:"is_active"`
}

type ListUserRolesResponse struct {
	UserID uuid.UUID          `json:"user_id"`
	Roles  []UserRoleListItem `json:"roles"`
	Total  int                `json:"total"`
}

type RemoveRoleRequest struct {
	RoleID uuid.UUID `json:"role_id" binding:"required"`
}

type ReplaceRolesRequest struct {
	RoleIDs   []uuid.UUID `json:"role_ids" binding:"required,min=1"`
	ExpiresAt *time.Time  `json:"expires_at"`
}
