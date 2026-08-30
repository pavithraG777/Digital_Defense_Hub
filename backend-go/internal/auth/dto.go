package auth

import (
	"time"

	"github.com/google/uuid"
)

type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required,min=8"`
	IPAddress  string `json:"ip_address,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
}

type LoginResponse struct {
	AccessToken      string                     `json:"access_token"`
	RefreshToken     string                     `json:"refresh_token,omitempty"`
	TokenType        string                     `json:"token_type"`
	ExpiresInSeconds int64                      `json:"expires_in_seconds"`
	User             UserResponse               `json:"user"`
	Risk             *AdaptiveLoginRiskResponse `json:"risk,omitempty"`
}

// AdaptiveLoginRiskResponse is the publicly serializable surface for the auth
// risk posture signal. It can be attached to login responses to keep risk
// explanations close to the session decision.
type AdaptiveLoginRiskResponse struct {
	RiskScore         int      `json:"risk_score"`
	RiskLevel         string   `json:"risk_level"`
	RequiresStepUpMFA bool     `json:"requires_step_up_mfa"`
	RiskFlags         []string `json:"risk_flags"`
	Summary           string   `json:"summary"`
}

// LoginResult is either a completed login or an MFA challenge. It never
// contains tokens while MFA is still pending.
type LoginResult struct {
	Login        *LoginResponse
	MFAChallenge *MFAChallengeResponse
	Risk         *AdaptiveLoginRiskResponse
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

// ChangePasswordRequest contains the current password,
// new password, and confirmation password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,min=8"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=128"`
	ConfirmPassword string `json:"confirm_password" binding:"required,min=8,max=128"`
}

// ChangePasswordResponse confirms that the password was changed
// and all existing sessions were terminated.
type ChangePasswordResponse struct {
	PasswordChanged    bool `json:"password_changed"`
	SessionsTerminated bool `json:"sessions_terminated"`
	LoginRequired      bool `json:"login_required"`
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
