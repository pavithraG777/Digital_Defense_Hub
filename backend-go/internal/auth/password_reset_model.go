package auth

import (
	"time"

	"github.com/google/uuid"
)

// PasswordResetToken represents a password reset request
// stored in the password_reset_tokens table.
type PasswordResetToken struct {
	ID                 uuid.UUID
	UserID             uuid.UUID
	TokenHash          string
	RequestedIPAddress *string
	RequestedDevice    *string
	ExpiresAt          time.Time
	UsedAt             *time.Time
	RevokedAt          *time.Time
	Status             string
	CreatedAt          time.Time
}
