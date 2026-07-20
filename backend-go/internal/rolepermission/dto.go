package rolepermission

import (
	"time"

	"github.com/google/uuid"
)

type AssignPermissionsRequest struct {
	PermissionIDs []uuid.UUID `json:"permission_ids" binding:"required,min=1"`
	ExpiresAt     *time.Time  `json:"expires_at"`
}

type AssignedPermissionItem struct {
	ID           uuid.UUID  `json:"id"`
	RoleID       uuid.UUID  `json:"role_id"`
	PermissionID uuid.UUID  `json:"permission_id"`
	GrantedBy    *uuid.UUID `json:"granted_by,omitempty"`
	GrantedAt    time.Time  `json:"granted_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	IsActive     bool       `json:"is_active"`
}

type AssignPermissionsResponse struct {
	RoleID              uuid.UUID                `json:"role_id"`
	AssignedPermissions []AssignedPermissionItem `json:"assigned_permissions"`
	AssignedCount       int                      `json:"assigned_count"`
	SkippedCount        int                      `json:"skipped_count"`
}

type RolePermissionListItem struct {
	MappingID      uuid.UUID  `json:"mapping_id"`
	PermissionID   uuid.UUID  `json:"permission_id"`
	PermissionCode string     `json:"permission_code"`
	PermissionName string     `json:"permission_name"`
	ModuleName     string     `json:"module_name"`
	ActionName     string     `json:"action_name"`
	Description    *string    `json:"description,omitempty"`
	RiskLevel      string     `json:"risk_level"`
	GrantedBy      *uuid.UUID `json:"granted_by,omitempty"`
	GrantedAt      time.Time  `json:"granted_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	IsActive       bool       `json:"is_active"`
}

type ListRolePermissionsResponse struct {
	RoleID      uuid.UUID                `json:"role_id"`
	Permissions []RolePermissionListItem `json:"permissions"`
	Total       int                      `json:"total"`
}

type RemovePermissionRequest struct {
	PermissionID uuid.UUID `json:"permission_id" binding:"required"`
}

type ReplacePermissionsRequest struct {
	PermissionIDs []uuid.UUID `json:"permission_ids" binding:"required,min=1"`
	ExpiresAt     *time.Time  `json:"expires_at"`
}
