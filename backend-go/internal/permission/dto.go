package permission

import "github.com/google/uuid"

type CreatePermissionRequest struct {
	PermissionCode string  `json:"permission_code" binding:"required"`
	PermissionName string  `json:"permission_name" binding:"required"`
	ModuleName     string  `json:"module_name" binding:"required"`
	ActionName     string  `json:"action_name" binding:"required"`
	Description    *string `json:"description"`
	RiskLevel      string  `json:"risk_level" binding:"required"`
	IsSystem       bool    `json:"is_system"`
	Status         string  `json:"status"`
}

type CreatePermissionResponse struct {
	ID             uuid.UUID `json:"id"`
	PermissionCode string    `json:"permission_code"`
	PermissionName string    `json:"permission_name"`
	ModuleName     string    `json:"module_name"`
	ActionName     string    `json:"action_name"`
	Description    *string   `json:"description,omitempty"`
	RiskLevel      string    `json:"risk_level"`
	IsSystem       bool      `json:"is_system"`
	Status         string    `json:"status"`
}

type ListPermissionsRequest struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Search   string `form:"search"`
	Module   string `form:"module"`
	Status   string `form:"status"`
}

type PermissionListItem struct {
	ID             uuid.UUID `json:"id"`
	PermissionCode string    `json:"permission_code"`
	PermissionName string    `json:"permission_name"`
	ModuleName     string    `json:"module_name"`
	ActionName     string    `json:"action_name"`
	RiskLevel      string    `json:"risk_level"`
	IsSystem       bool      `json:"is_system"`
	Status         string    `json:"status"`
}

type ListPermissionsResponse struct {
	Permissions []PermissionListItem `json:"permissions"`
	Total       int                  `json:"total"`
	Page        int                  `json:"page"`
	PageSize    int                  `json:"page_size"`
	TotalPages  int                  `json:"total_pages"`
}

type GetPermissionResponse struct {
	ID               uuid.UUID `json:"id"`
	PermissionCode   string    `json:"permission_code"`
	PermissionName   string    `json:"permission_name"`
	ModuleName       string    `json:"module_name"`
	ActionName       string    `json:"action_name"`
	Description      *string   `json:"description,omitempty"`
	RiskLevel        string    `json:"risk_level"`
	RequiresApproval bool      `json:"is_system"`
	Status           string    `json:"status"`
}

type UpdatePermissionRequest struct {
	PermissionName *string `json:"permission_name"`
	ModuleName     *string `json:"module_name"`
	ActionName     *string `json:"action_name"`
	Description    *string `json:"description"`
	RiskLevel      *string `json:"risk_level"`
	Status         *string `json:"status"`
}
