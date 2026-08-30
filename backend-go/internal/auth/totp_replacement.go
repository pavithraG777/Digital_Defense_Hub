package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const totpReplacementLifetime = 10 * time.Minute

type totpReplacementToken struct {
	UserID         uuid.UUID `json:"user_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Secret         string    `json:"secret"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (s *Service) StartTOTPReplacement(ctx context.Context, userID uuid.UUID) (*StartTOTPReplacementResponse, error) {
	if len(s.mfaMasterKey) != 32 {
		return nil, ErrMFASecretEncryptionUnavailable
	}
	user, err := s.repository.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !user.MFAEnabled {
		return nil, errors.New("MFA must be enabled before replacing an authenticator")
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(totpReplacementToken{UserID: user.ID, OrganizationID: user.OrganizationID, Secret: secret, ExpiresAt: time.Now().UTC().Add(totpReplacementLifetime)})
	if err != nil {
		return nil, err
	}
	encrypted, err := EncryptTOTPSecret(s.mfaMasterKey, string(payload))
	if err != nil {
		return nil, err
	}
	return &StartTOTPReplacementResponse{
		ProvisioningURI: GenerateTOTPProvisioningURI(user.Username, "Cyber Security Platform", secret),
		EnrollmentToken: base64.RawURLEncoding.EncodeToString(encrypted),
	}, nil
}

func (s *Service) ConfirmTOTPReplacement(ctx context.Context, userID uuid.UUID, request ConfirmTOTPReplacementRequest) (*ConfirmTOTPReplacementResponse, error) {
	encrypted, err := base64.RawURLEncoding.DecodeString(request.EnrollmentToken)
	if err != nil {
		return nil, ErrMFAChallengeInvalid
	}
	plaintext, err := DecryptTOTPSecret(s.mfaMasterKey, encrypted)
	if err != nil {
		return nil, ErrMFAChallengeInvalid
	}
	var token totpReplacementToken
	if json.Unmarshal([]byte(plaintext), &token) != nil || token.UserID != userID || !time.Now().UTC().Before(token.ExpiresAt) {
		return nil, ErrMFAChallengeInvalid
	}
	user, err := s.repository.FindUserByID(ctx, userID)
	if err != nil || token.OrganizationID != user.OrganizationID || !user.MFAEnabled {
		return nil, ErrMFAChallengeInvalid
	}
	if !ValidateTOTPCode(token.Secret, request.TOTPCode, time.Now().UTC(), totpDefaultPeriod, totpDefaultDigits) {
		return nil, ErrInvalidTOTPCode
	}
	recoveryCodes, err := GenerateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(recoveryCodes))
	for index, code := range recoveryCodes {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if hashErr != nil {
			return nil, fmt.Errorf("hash replacement recovery code: %w", hashErr)
		}
		hashes[index] = string(hash)
	}
	secret, err := EncryptTOTPSecret(s.mfaMasterKey, token.Secret)
	if err != nil {
		return nil, err
	}
	if err := s.repository.SaveMFAEnrollmentSecret(ctx, user.ID, user.OrganizationID, secret, hashes); err != nil {
		return nil, err
	}
	return &ConfirmTOTPReplacementResponse{MFAEnabled: true, RecoveryCodes: recoveryCodes}, nil
}
