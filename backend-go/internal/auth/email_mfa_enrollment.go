package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (s *Service) StartEmailMFAEnrollment(ctx context.Context, userID uuid.UUID) (*StartEmailMFAEnrollmentResponse, error) {
	user, err := s.repository.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if s.mfaDelivery == nil || !user.EmailVerified {
		return nil, ErrMFADeliveryUnavailable
	}
	code, err := generateMFAOTP()
	if err != nil {
		return nil, fmt.Errorf("generate email enrollment OTP: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().UTC().Add(mfaChallengeLifetime)
	challengeID, err := s.repository.CreateMFAChallenge(ctx, user.ID, user.OrganizationID, string(hash), string(hash), expiresAt)
	if err != nil {
		return nil, fmt.Errorf("create email enrollment challenge: %w", err)
	}
	if err := s.mfaDelivery.DeliverMFAOTP(ctx, user.OfficialEmail, code); err != nil {
		_ = s.repository.CancelMFAChallenge(ctx, challengeID)
		return nil, fmt.Errorf("%w: %v", ErrMFADeliveryUnavailable, err)
	}
	return &StartEmailMFAEnrollmentResponse{MFAChallengeID: challengeID.String(), ExpiresInSeconds: int64(mfaChallengeLifetime.Seconds())}, nil
}

func (s *Service) ConfirmEmailMFAEnrollment(ctx context.Context, userID uuid.UUID, request ConfirmEmailMFAEnrollmentRequest) (*ConfirmMFAEnrollmentResponse, error) {
	challengeID, err := uuid.Parse(request.MFAChallengeID)
	if err != nil {
		return nil, ErrMFAChallengeInvalid
	}
	challenge, err := s.repository.VerifyAndConsumeMFAChallenge(ctx, challengeID, request.EmailCode, request.EmailCode)
	if err != nil {
		return nil, err
	}
	user, err := s.repository.FindUserByID(ctx, userID)
	if err != nil || challenge.UserID != user.ID || challenge.OrganizationID != user.OrganizationID {
		return nil, ErrMFAChallengeInvalid
	}
	if err := s.repository.EnableMFA(ctx, user.ID, user.OrganizationID); err != nil {
		return nil, err
	}
	return &ConfirmMFAEnrollmentResponse{MFAEnabled: true}, nil
}
