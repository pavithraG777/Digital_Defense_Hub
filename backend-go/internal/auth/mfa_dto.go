package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type VerifyMFARequest struct {
	MFAChallengeID string `json:"mfa_challenge_id" binding:"omitempty,uuid"`
	EmailCode      string `json:"email_code" binding:"omitempty,len=6,numeric"`
	TOTPCode       string `json:"totp_code" binding:"omitempty,len=6,numeric"`
	RecoveryCode   string `json:"recovery_code" binding:"omitempty,min=8,max=32"`
}

type MFAOTPDelivery interface {
	DeliverMFAOTP(ctx context.Context, emailAddress, emailCode string) error
}

type MFAChallengeRepository interface {
	FindUserByID(ctx context.Context, userID uuid.UUID) (*User, error)
	IsDeviceTrusted(ctx context.Context, user, org uuid.UUID, device string) (bool, error)
	CreateMFAChallenge(ctx context.Context, userID, organizationID uuid.UUID, emailHash, smsHash string, expiresAt time.Time) (uuid.UUID, error)
	CancelMFAChallenge(ctx context.Context, id uuid.UUID) error
	VerifyAndConsumeMFAChallenge(ctx context.Context, id uuid.UUID, emailCode, smsCode string) (*MFAChallenge, error)
}

type StartMFAEnrollmentResponse struct {
	ProvisioningURI string   `json:"provisioning_uri"`
	RecoveryCodes   []string `json:"recovery_codes"`
}

type ConfirmMFAEnrollmentRequest struct {
	TOTPCode string `json:"totp_code" binding:"required,len=6,numeric"`
}

type ConfirmMFAEnrollmentResponse struct {
	MFAEnabled bool `json:"mfa_enabled"`
}

type StartEmailMFAEnrollmentResponse struct {
	MFAChallengeID   string `json:"mfa_challenge_id"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

type ConfirmEmailMFAEnrollmentRequest struct {
	MFAChallengeID string `json:"mfa_challenge_id" binding:"required,uuid"`
	EmailCode      string `json:"email_code" binding:"required,len=6,numeric"`
}

type StartTOTPReplacementResponse struct {
	ProvisioningURI string `json:"provisioning_uri"`
	EnrollmentToken string `json:"enrollment_token"`
}

type ConfirmTOTPReplacementRequest struct {
	EnrollmentToken string `json:"enrollment_token" binding:"required"`
	TOTPCode        string `json:"totp_code" binding:"required,len=6,numeric"`
}

type ConfirmTOTPReplacementResponse struct {
	MFAEnabled    bool     `json:"mfa_enabled"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type MFAChallengeResponse struct {
	MFARequired      bool   `json:"mfa_required"`
	MFAChallengeID   string `json:"mfa_challenge_id"`
	MFAChallengeType string `json:"mfa_challenge_type,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}
