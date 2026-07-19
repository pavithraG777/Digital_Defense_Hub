package auth

import (
	"time"

	"github.com/google/uuid"
)

type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required,min=8"`
}

type LoginResponse struct {
	AccessToken      string       `json:"access_token"`
	RefreshToken     string       `json:"refresh_token,omitempty"`
	TokenType        string       `json:"token_type"`
	ExpiresInSeconds int64        `json:"expires_in_seconds"`
	User             UserResponse `json:"user"`
}

type UserResponse struct {
	ID                 string   `json:"id"`
	Username           string   `json:"username"`
	OfficialEmail      string   `json:"official_email"`
	DisplayName        string   `json:"display_name"`
	UserType           string   `json:"user_type"`
	AccountStatus      string   `json:"account_status"`
	MustChangePassword bool     `json:"must_change_password"`
	MFAEnabled         bool     `json:"mfa_enabled"`
	Roles              []string `json:"roles"`
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
