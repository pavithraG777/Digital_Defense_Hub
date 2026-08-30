package auth

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                    uuid.UUID  `json:"id"`
	OrganizationID        uuid.UUID  `json:"organization_id"`
	Username              string     `json:"username"`
	OfficialEmail         string     `json:"official_email"`
	PasswordHash          string     `json:"-"`
	UserType              string     `json:"user_type"`
	AccountStatus         string     `json:"account_status"`
	EmailVerified         bool       `json:"email_verified"`
	PhoneVerified         bool       `json:"phone_verified"`
	MFAEnabled            bool       `json:"mfa_enabled"`
	MFASecretEncrypted    []byte     `json:"-"`
	MFARecoveryCodeHashes []string   `json:"-"`
	MustChangePassword    bool       `json:"must_change_password"`
	FailedLoginAttempts   int        `json:"failed_login_attempts"`
	LockedUntil           *time.Time `json:"locked_until,omitempty"`
	PasswordChangedAt     *time.Time `json:"password_changed_at,omitempty"`
	LastLoginAt           *time.Time `json:"last_login_at,omitempty"`
	LastLogoutAt          *time.Time `json:"last_logout_at,omitempty"`
	PreferredLanguage     string     `json:"preferred_language"`
	Timezone              string     `json:"timezone"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	DeletedAt             *time.Time `json:"deleted_at,omitempty"`
}

type MFAChallenge struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	OrganizationID  uuid.UUID
	EmailCodeHash   string
	SMSCodeHash     string
	Status          string
	Attempts        int
	MaximumAttempts int
	ExpiresAt       time.Time
}

type UserProfile struct {
	ID                     uuid.UUID `json:"id"`
	UserID                 uuid.UUID `json:"user_id"`
	EmployeeCode           *string   `json:"employee_code,omitempty"`
	FirstName              string    `json:"first_name"`
	MiddleName             *string   `json:"middle_name,omitempty"`
	LastName               *string   `json:"last_name,omitempty"`
	DisplayName            *string   `json:"display_name,omitempty"`
	Designation            *string   `json:"designation,omitempty"`
	EmploymentType         *string   `json:"employment_type,omitempty"`
	OfficialPhone          *string   `json:"official_phone,omitempty"`
	ProfilePhotoPath       *string   `json:"profile_photo_path,omitempty"`
	SecurityClearanceLevel string    `json:"security_clearance_level"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type Role struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	RoleCode       string    `json:"role_code"`
	RoleName       string    `json:"role_name"`
	RoleScope      string    `json:"role_scope"`
	PriorityLevel  int       `json:"priority_level"`
	Status         string    `json:"status"`
}

type RefreshToken struct {
	ID                uuid.UUID  `json:"id"`
	UserID            uuid.UUID  `json:"user_id"`
	SessionID         uuid.UUID  `json:"session_id"`
	TokenHash         string     `json:"-"`
	IssuedAt          time.Time  `json:"issued_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	ReplacedByTokenID *uuid.UUID `json:"replaced_by_token_id,omitempty"`
	RevocationReason  *string    `json:"revocation_reason,omitempty"`
	Status            string     `json:"status"`
	CreatedAt         time.Time  `json:"created_at"`
}
