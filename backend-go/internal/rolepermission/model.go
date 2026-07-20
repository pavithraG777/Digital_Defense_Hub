package rolepermission

import (
	"time"

	"github.com/google/uuid"
)

type RolePermission struct {
	ID           uuid.UUID  `json:"id"`
	RoleID       uuid.UUID  `json:"role_id"`
	PermissionID uuid.UUID  `json:"permission_id"`
	GrantedBy    *uuid.UUID `json:"granted_by,omitempty"`
	GrantedAt    time.Time  `json:"granted_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	IsActive     bool       `json:"is_active"`
	CreatedAt    time.Time  `json:"created_at"`
}
