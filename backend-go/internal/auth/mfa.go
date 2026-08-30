package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const mfaChallengeLifetime = 10 * time.Minute

func (s *Service) createMFAChallenge(ctx context.Context, user *User) (*MFAChallengeResponse, error) {
	challengeType := "EMAIL"
	usesTOTP := len(user.MFASecretEncrypted) > 0
	if usesTOTP {
		challengeType = "EMAIL_OR_TOTP"
	} else if s.mfaDelivery == nil || !user.EmailVerified {
		return nil, ErrMFADeliveryUnavailable
	}
	emailCode, err := generateMFAOTP()
	if err != nil {
		return nil, fmt.Errorf("generate email OTP: %w", err)
	}
	emailHash, err := bcrypt.GenerateFromPassword([]byte(emailCode), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().UTC().Add(mfaChallengeLifetime)
	// The existing schema retains its second hash column for compatibility;
	// email-only MFA intentionally stores the same one-time secret there.
	id, err := s.repository.CreateMFAChallenge(ctx, user.ID, user.OrganizationID, string(emailHash), string(emailHash), expiresAt)
	if err != nil {
		return nil, fmt.Errorf("create MFA challenge: %w", err)
	}
	if s.mfaDelivery != nil && user.EmailVerified {
		if err := s.mfaDelivery.DeliverMFAOTP(ctx, user.OfficialEmail, emailCode); err != nil && !usesTOTP {
			_ = s.repository.CancelMFAChallenge(ctx, id)
			return nil, fmt.Errorf("%w: %v", ErrMFADeliveryUnavailable, err)
		}
	}
	return &MFAChallengeResponse{MFARequired: true, MFAChallengeID: id.String(), MFAChallengeType: challengeType, ExpiresInSeconds: int64(mfaChallengeLifetime.Seconds())}, nil
}

func (s *Service) VerifyMFA(ctx context.Context, request VerifyMFARequest) (*LoginResponse, error) {
	id, err := uuid.Parse(request.MFAChallengeID)
	if err != nil {
		return nil, ErrMFAChallengeInvalid
	}
	method, err := selectedMFAMethod(request)
	if err != nil {
		return nil, err
	}
	var challenge *MFAChallenge
	if method == "EMAIL" {
		challenge, err = s.repository.VerifyAndConsumeMFAChallenge(ctx, id, request.EmailCode, request.EmailCode)
	} else {
		challenge, err = s.repository.FindActiveMFAChallenge(ctx, id)
	}
	if err != nil {
		return nil, err
	}
	user, err := s.repository.FindUserByID(ctx, challenge.UserID)
	if err != nil || user.OrganizationID != challenge.OrganizationID || !user.MFAEnabled {
		return nil, ErrMFAChallengeInvalid
	}
	if method != "EMAIL" {
		if len(user.MFASecretEncrypted) == 0 {
			return nil, s.repository.RecordMFAChallengeFailure(ctx, id)
		}
		if method == "TOTP" {
			secret, decryptErr := DecryptTOTPSecret(s.mfaMasterKey, user.MFASecretEncrypted)
			if decryptErr != nil {
				return nil, fmt.Errorf("decrypt MFA secret: %w", decryptErr)
			}
			if !ValidateTOTPCode(secret, request.TOTPCode, time.Now().UTC(), totpDefaultPeriod, totpDefaultDigits) {
				return nil, s.repository.RecordMFAChallengeFailure(ctx, id)
			}
			challenge, err = s.repository.ConsumeMFAChallenge(ctx, id, user.ID, user.OrganizationID)
		} else {
			matchedHash := matchingRecoveryCodeHash(user.MFARecoveryCodeHashes, request.RecoveryCode)
			if matchedHash == "" {
				return nil, s.repository.RecordMFAChallengeFailure(ctx, id)
			}
			challenge, err = s.repository.ConsumeRecoveryCodeAndMFAChallenge(ctx, id, user.ID, user.OrganizationID, matchedHash)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := s.validateAccountStatus(user); err != nil {
		return nil, err
	}
	roles, err := s.repository.GetActiveRoleCodes(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("retrieve user roles: %w", err)
	}
	if len(roles) == 0 {
		return nil, ErrNoActiveRoles
	}
	return s.issueLoginTokens(ctx, user, user.Username, roles, true)
}

func selectedMFAMethod(request VerifyMFARequest) (string, error) {
	methods := 0
	selected := ""
	if request.EmailCode != "" {
		methods++
		selected = "EMAIL"
	}
	if request.TOTPCode != "" {
		methods++
		selected = "TOTP"
	}
	if request.RecoveryCode != "" {
		methods++
		selected = "RECOVERY"
	}
	if methods != 1 {
		return "", ErrMFAChallengeInvalid
	}
	return selected, nil
}

func matchingRecoveryCodeHash(hashes []string, recoveryCode string) string {
	for _, hash := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(recoveryCode)) == nil {
			return hash
		}
	}
	return ""
}

func generateMFAOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
