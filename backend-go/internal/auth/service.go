package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials       = errors.New("invalid username/email or password")
	ErrAccountPending           = errors.New("account activation is pending")
	ErrAccountInactive          = errors.New("account is inactive")
	ErrAccountSuspended         = errors.New("account is suspended")
	ErrAccountLocked            = errors.New("account is temporarily locked")
	ErrNoActiveRoles            = errors.New("user has no active roles")
	ErrCurrentPasswordIncorrect = errors.New("current password is incorrect")

	ErrNewPasswordMismatch = errors.New("new password and confirmation password do not match")

	ErrNewPasswordSame = errors.New("new password must be different from the current password")

	ErrWeakPassword  = errors.New("new password must contain at least 8 characters")
	ErrEmailNotFound = errors.New("no account exists with the provided email")

	ErrPasswordResetExpired = errors.New("password reset token has expired")

	ErrPasswordResetAlreadyUsed       = errors.New("password reset token has already been used")
	ErrMFAChallengeInvalid            = errors.New("MFA challenge is invalid, expired, or already used")
	ErrMFAChallengeLocked             = errors.New("MFA challenge has been locked")
	ErrMFADeliveryUnavailable         = errors.New("MFA delivery is unavailable")
	ErrMFASecretEncryptionUnavailable = errors.New("MFA secret encryption is unavailable")
	ErrMFAEnrollmentNotConfigured     = errors.New("MFA enrollment is not configured")
	ErrInvalidTOTPCode                = errors.New("invalid TOTP code")
	ErrStepUpMFARequired              = errors.New("adaptive MFA enrollment is required for this login risk")
)

// AdaptiveLoginRiskAssessment describes the identity hardening posture for a
// login or a session bootstrap decision. The values are intentionally simple and
// deterministic so they can be unit tested and exposed through the API.
type AdaptiveLoginRiskAssessment struct {
	RiskScore         int      `json:"risk_score"`
	RiskLevel         string   `json:"risk_level"`
	RequiresStepUpMFA bool     `json:"requires_step_up_mfa"`
	RiskFlags         []string `json:"risk_flags"`
	Summary           string   `json:"summary"`
}

const (
	maxFailedLoginAttempts = 5
	accountLockDuration    = 15 * time.Minute
)

type Service struct {
	repository   *Repository
	jwtManager   *JWTManager
	mfaDelivery  MFAOTPDelivery
	mfaMasterKey []byte
}

func NewService(
	repository *Repository,
	jwtManager *JWTManager,
	mfaDelivery MFAOTPDelivery,
	mfaMasterKey []byte,
) *Service {
	return &Service{
		repository:   repository,
		jwtManager:   jwtManager,
		mfaDelivery:  mfaDelivery,
		mfaMasterKey: mfaMasterKey,
	}
}

func (s *Service) Login(
	ctx context.Context,
	request LoginRequest,
) (*LoginResult, error) {
	identifier := strings.TrimSpace(request.Identifier)

	if identifier == "" || request.Password == "" {
		return nil, ErrInvalidCredentials
	}

	user, displayName, err :=
		s.repository.FindUserByIdentifier(ctx, identifier)

	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf(
			"failed to retrieve user: %w",
			err,
		)
	}

	if err := s.validateAccountStatus(user); err != nil {
		return nil, err
	}

	if !VerifyPassword(request.Password, user.PasswordHash) {
		if err := s.handleFailedLogin(ctx, user); err != nil {
			return nil, fmt.Errorf(
				"failed to process unsuccessful login: %w",
				err,
			)
		}

		return nil, ErrInvalidCredentials
	}

	roles, err := s.repository.GetActiveRoleCodes(
		ctx,
		user.ID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to retrieve user roles: %w",
			err,
		)
	}

	if len(roles) == 0 {
		return nil, ErrNoActiveRoles
	}

	deviceTrusted := false
	if strings.TrimSpace(request.DeviceID) != "" {
		deviceTrusted, _ = s.repository.IsDeviceTrusted(ctx, user.ID, user.OrganizationID, request.DeviceID)
	}
	loginRisk := ScoreAdaptiveLoginRiskWithDevice(
		strings.TrimSpace(request.IPAddress),
		strings.TrimSpace(request.UserAgent),
		user.MFAEnabled,
		strings.TrimSpace(request.DeviceID), deviceTrusted,
	)
	_ = s.repository.RecordLoginRisk(ctx, user.ID, user.OrganizationID, request.DeviceID, request.IPAddress, loginRisk)
	loginRiskResponse := &AdaptiveLoginRiskResponse{
		RiskScore:         loginRisk.RiskScore,
		RiskLevel:         loginRisk.RiskLevel,
		RequiresStepUpMFA: loginRisk.RequiresStepUpMFA,
		RiskFlags:         loginRisk.RiskFlags,
		Summary:           loginRisk.Summary,
	}

	// A first-time user cannot complete a step-up challenge until an MFA
	// method has been enrolled. Issue the normal session so the frontend can
	// immediately redirect the user to the mandatory MFA enrollment route;
	// protected navigation blocks the workspace until enrollment is complete.
	if user.MFAEnabled {
		challenge, err := s.createMFAChallenge(ctx, user)
		if err != nil {
			return nil, err
		}
		return &LoginResult{
			MFAChallenge: challenge,
			Risk:         loginRiskResponse,
		}, nil
	}

	loginResponse, err := s.issueLoginTokens(ctx, user, displayName, roles, false)
	if err != nil {
		return nil, err
	}
	loginResponse.Risk = loginRiskResponse
	return &LoginResult{Login: loginResponse, Risk: loginRiskResponse}, nil
}

func (s *Service) issueLoginTokens(
	ctx context.Context,
	user *User,
	displayName string,
	roles []string,
	mfaVerified bool,
) (*LoginResponse, error) {

	sessionID := uuid.New()

	accessToken, accessTokenExpiresAt, err :=
		s.jwtManager.GenerateAccessToken(
			user,
			roles,
			sessionID,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate access token: %w",
			err,
		)
	}

	generatedRefreshToken, err := GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate refresh token: %w",
			err,
		)
	}

	if err := s.repository.CreateSession(
		ctx,
		sessionID,
		user.ID,
		user.OrganizationID,
		accessToken,
		accessTokenExpiresAt,
		mfaVerified,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to create login session: %w",
			err,
		)
	}

	if err := s.repository.CreateRefreshToken(
		ctx,
		generatedRefreshToken.ID,
		user.ID,
		sessionID,
		generatedRefreshToken.Token,
		generatedRefreshToken.ExpiresAt,
	); err != nil {
		_ = s.repository.LogoutSession(
			ctx,
			sessionID,
			user.ID,
			user.OrganizationID,
		)

		return nil, fmt.Errorf(
			"failed to create refresh token: %w",
			err,
		)
	}

	if err := s.repository.RecordSuccessfulLogin(
		ctx,
		user.ID,
	); err != nil {
		_ = s.repository.RevokeSessionRefreshTokens(
			ctx,
			sessionID,
			"LOGIN_PROCESS_FAILED",
		)

		_ = s.repository.LogoutSession(
			ctx,
			sessionID,
			user.ID,
			user.OrganizationID,
		)

		return nil, fmt.Errorf(
			"failed to record successful login: %w",
			err,
		)
	}

	if strings.TrimSpace(displayName) == "" {
		displayName = user.Username
	}

	expiresInSeconds := int64(
		time.Until(accessTokenExpiresAt).Seconds(),
	)

	if expiresInSeconds < 0 {
		expiresInSeconds = 0
	}

	response := &LoginResponse{
		AccessToken:      accessToken,
		RefreshToken:     generatedRefreshToken.Token,
		TokenType:        "Bearer",
		ExpiresInSeconds: expiresInSeconds,
		User: UserResponse{
			ID:                 user.ID.String(),
			Username:           user.Username,
			OfficialEmail:      user.OfficialEmail,
			DisplayName:        displayName,
			UserType:           user.UserType,
			AccountStatus:      user.AccountStatus,
			MustChangePassword: user.MustChangePassword,
			MFAEnabled:         user.MFAEnabled,
			Roles:              roles,
		},
	}

	return response, nil
}

// ScoreAdaptiveLoginRisk derives a basic adaptive login-risk decision from
// IP-address, user-agent and MFA posture. It closes the logical gap between a
// raw login password check and the advanced identity hardening roadmap so the
// auth service can produce a measurable posture signal.
func ScoreAdaptiveLoginRisk(ipAddress string, userAgent string, mfaEnabled bool) AdaptiveLoginRiskAssessment {
	return ScoreAdaptiveLoginRiskWithDevice(ipAddress, userAgent, mfaEnabled, "", false)
}

func ScoreAdaptiveLoginRiskWithDevice(ipAddress string, userAgent string, mfaEnabled bool, deviceID string, deviceTrusted bool) AdaptiveLoginRiskAssessment {
	ipCandidate := strings.TrimSpace(ipAddress)
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	flags := make([]string, 0, 4)
	riskScore := 5

	if ipCandidate == "" {
		flags = append(flags, "missing_client_ip")
		riskScore += 20
	}

	if strings.HasPrefix(ipCandidate, "127.") || strings.HasPrefix(ipCandidate, "10.") || strings.HasPrefix(ipCandidate, "192.168.") || strings.HasPrefix(ipCandidate, "172.") || strings.EqualFold(ipCandidate, "localhost") {
		// Local development / private-network sources are not trusted for external-origin evaluation.
		flags = append(flags, "private_or_local_ip")
		riskScore += 8
	} else if strings.Contains(ipCandidate, ":") {
		flags = append(flags, "ipv6_source")
		riskScore += 5
	}

	if strings.Contains(ua, "curl") || strings.Contains(ua, "python") || strings.Contains(ua, "bot") || strings.Contains(ua, "go-http-client") {
		flags = append(flags, "non_browser_client")
		riskScore += 25
	}

	if !mfaEnabled {
		flags = append(flags, "mfa_not_enforced")
		riskScore += 15
	}
	if strings.TrimSpace(deviceID) == "" {
		flags = append(flags, "device_identifier_missing")
		riskScore += 10
	} else if !deviceTrusted {
		flags = append(flags, "untrusted_device")
		riskScore += 20
	} else {
		riskScore -= 10
	}

	if len(flags) > 2 {
		riskScore += 10
	}

	if riskScore < 30 {
		riskScore = 30
	}
	if riskScore > 95 {
		riskScore = 95
	}

	riskLevel := "LOW"
	requiresStepUpMFA := false
	if riskScore >= 70 {
		riskLevel = "HIGH"
		requiresStepUpMFA = true
	} else if riskScore >= 45 {
		riskLevel = "MEDIUM"
		requiresStepUpMFA = true
	} else {
		riskLevel = "LOW"
	}

	summary := "login posture is within the trusted baseline"
	if requiresStepUpMFA {
		summary = "risk posture requires adaptive MFA or step-up validation"
	}

	return AdaptiveLoginRiskAssessment{
		RiskScore:         riskScore,
		RiskLevel:         riskLevel,
		RequiresStepUpMFA: requiresStepUpMFA,
		RiskFlags:         flags,
		Summary:           summary,
	}
}

func (s *Service) StartMFAEnrollment(
	ctx context.Context,
	userID uuid.UUID,
) (*StartMFAEnrollmentResponse, error) {
	if len(s.mfaMasterKey) != 32 {
		return nil, ErrMFASecretEncryptionUnavailable
	}

	user, err := s.repository.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if len(user.MFASecretEncrypted) > 0 {
		return nil, fmt.Errorf("TOTP is already enrolled for this user")
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	encryptedSecret, err := EncryptTOTPSecret(s.mfaMasterKey, secret)
	if err != nil {
		return nil, err
	}

	recoveryCodes, err := GenerateRecoveryCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate MFA recovery codes: %w", err)
	}

	recoveryCodeHashes := make([]string, len(recoveryCodes))
	for i, code := range recoveryCodes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash MFA recovery code: %w", err)
		}
		recoveryCodeHashes[i] = string(hash)
	}

	if err := s.repository.SaveMFAEnrollmentSecret(
		ctx,
		user.ID,
		user.OrganizationID,
		encryptedSecret,
		recoveryCodeHashes,
	); err != nil {
		return nil, err
	}

	provisioningURI := GenerateTOTPProvisioningURI(
		user.Username,
		"Cyber Security Platform",
		secret,
	)

	return &StartMFAEnrollmentResponse{
		ProvisioningURI: provisioningURI,
		RecoveryCodes:   recoveryCodes,
	}, nil
}

func (s *Service) ConfirmMFAEnrollment(
	ctx context.Context,
	userID uuid.UUID,
	request ConfirmMFAEnrollmentRequest,
) (*ConfirmMFAEnrollmentResponse, error) {
	if len(s.mfaMasterKey) != 32 {
		return nil, ErrMFASecretEncryptionUnavailable
	}

	user, err := s.repository.FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if len(user.MFASecretEncrypted) == 0 {
		return nil, ErrMFAEnrollmentNotConfigured
	}

	secret, err := DecryptTOTPSecret(s.mfaMasterKey, user.MFASecretEncrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt MFA secret: %w", err)
	}

	if !ValidateTOTPCode(secret, request.TOTPCode, time.Now().UTC(), totpDefaultPeriod, totpDefaultDigits) {
		return nil, ErrInvalidTOTPCode
	}

	if err := s.repository.EnableMFA(
		ctx,
		user.ID,
		user.OrganizationID,
	); err != nil {
		return nil, err
	}

	return &ConfirmMFAEnrollmentResponse{MFAEnabled: true}, nil
}

func (s *Service) validateAccountStatus(
	user *User,
) error {
	status := strings.ToUpper(
		strings.TrimSpace(user.AccountStatus),
	)

	switch status {
	case "ACTIVE":
		return nil

	case "LOCKED":
		if user.LockedUntil == nil {
			return ErrAccountLocked
		}

		if time.Now().Before(*user.LockedUntil) {
			return ErrAccountLocked
		}

		return nil

	case "PENDING":
		return ErrAccountPending

	case "INACTIVE", "DISABLED":
		return ErrAccountInactive

	case "SUSPENDED", "BLOCKED":
		return ErrAccountSuspended

	default:
		return ErrAccountInactive
	}
}

func (s *Service) handleFailedLogin(
	ctx context.Context,
	user *User,
) error {
	nextFailedAttempt :=
		user.FailedLoginAttempts + 1

	if nextFailedAttempt >= maxFailedLoginAttempts {
		lockedUntil := time.Now().Add(
			accountLockDuration,
		)

		if err := s.repository.LockUser(
			ctx,
			user.ID,
			lockedUntil,
		); err != nil {
			return fmt.Errorf(
				"failed to lock account: %w",
				err,
			)
		}

		return nil
	}

	if err := s.repository.IncrementFailedLogin(
		ctx,
		user.ID,
	); err != nil {
		return fmt.Errorf(
			"failed to increment login attempts: %w",
			err,
		)
	}

	return nil
}

func (s *Service) Logout(
	ctx context.Context,
	userID uuid.UUID,
	organizationID uuid.UUID,
	sessionID uuid.UUID,
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if organizationID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}

	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	if err := s.repository.RevokeSessionRefreshTokens(
		ctx,
		sessionID,
		"USER_LOGOUT",
	); err != nil {
		return fmt.Errorf(
			"failed to revoke session refresh tokens: %w",
			err,
		)
	}

	if err := s.repository.LogoutSession(
		ctx,
		sessionID,
		userID,
		organizationID,
	); err != nil {
		return fmt.Errorf(
			"failed to logout session: %w",
			err,
		)
	}

	return nil
}

func (s *Service) ChangePassword(
	ctx context.Context,
	userID uuid.UUID,
	organizationID uuid.UUID,
	request ChangePasswordRequest,
) (*ChangePasswordResponse, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf(
			"user ID is required",
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"organization ID is required",
		)
	}

	currentPassword := request.CurrentPassword
	newPassword := request.NewPassword
	confirmPassword := request.ConfirmPassword

	if strings.TrimSpace(currentPassword) == "" {
		return nil, ErrCurrentPasswordIncorrect
	}

	if len(newPassword) < 8 {
		return nil, ErrWeakPassword
	}

	if newPassword != confirmPassword {
		return nil, ErrNewPasswordMismatch
	}

	user, err := s.repository.FindUserByID(
		ctx,
		userID,
	)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}

		return nil, fmt.Errorf(
			"failed to retrieve authenticated user: %w",
			err,
		)
	}

	if user.OrganizationID != organizationID {
		return nil, ErrUserNotFound
	}

	if err := s.validateAccountStatus(user); err != nil {
		return nil, err
	}

	if !VerifyPassword(
		currentPassword,
		user.PasswordHash,
	) {
		return nil, ErrCurrentPasswordIncorrect
	}

	if VerifyPassword(
		newPassword,
		user.PasswordHash,
	) {
		return nil, ErrNewPasswordSame
	}

	newPasswordHash, err :=
		bcrypt.GenerateFromPassword(
			[]byte(newPassword),
			bcrypt.DefaultCost,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to hash new password: %w",
			err,
		)
	}

	if err := s.repository.UpdatePassword(
		ctx,
		userID,
		organizationID,
		string(newPasswordHash),
	); err != nil {
		return nil, fmt.Errorf(
			"failed to update password: %w",
			err,
		)
	}

	if err := s.repository.RevokeAllUserRefreshTokens(
		ctx,
		userID,
		"PASSWORD_CHANGED",
	); err != nil {
		return nil, fmt.Errorf(
			"password changed but failed to revoke refresh tokens: %w",
			err,
		)
	}

	if err := s.LogoutAllSessions(
		ctx,
		userID,
	); err != nil {
		return nil, fmt.Errorf(
			"password changed but failed to terminate sessions: %w",
			err,
		)
	}

	return &ChangePasswordResponse{
		PasswordChanged:    true,
		SessionsTerminated: true,
		LoginRequired:      true,
	}, nil
}

func (s *Service) ForgotPassword(
	ctx context.Context,
	request ForgotPasswordRequest,
) (*ForgotPasswordResponse, error) {

	email := strings.TrimSpace(request.Email)

	if email == "" {
		return nil, ErrEmailNotFound
	}

	user, _, err := s.repository.FindUserByIdentifier(
		ctx,
		email,
	)

	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrEmailNotFound
		}

		return nil, fmt.Errorf(
			"failed to find user: %w",
			err,
		)
	}

	if err := s.repository.RevokePasswordResetTokensByUserID(
		ctx,
		user.ID,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to revoke previous password reset tokens: %w",
			err,
		)
	}

	generatedToken, err := GeneratePasswordResetToken()
	if err != nil {
		return nil, err
	}

	resetToken := &PasswordResetToken{
		ID:                 generatedToken.ID,
		UserID:             user.ID,
		TokenHash:          generatedToken.TokenHash,
		RequestedIPAddress: nil,
		RequestedDevice:    nil,
		ExpiresAt:          generatedToken.ExpiresAt,
		Status:             "ACTIVE",
	}

	if err := s.repository.CreatePasswordResetToken(
		ctx,
		resetToken,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to store password reset token: %w",
			err,
		)
	}

	return &ForgotPasswordResponse{
		Message:          "Password reset token generated successfully",
		ResetToken:       generatedToken.Token,
		ExpiresInSeconds: int64(time.Until(generatedToken.ExpiresAt).Seconds()),
	}, nil
}

func (s *Service) ResetPassword(
	ctx context.Context,
	request ResetPasswordRequest,
) (*ResetPasswordResponse, error) {
	rawToken := strings.TrimSpace(
		request.ResetToken,
	)

	newPassword := request.NewPassword
	confirmPassword := request.ConfirmPassword

	if rawToken == "" {
		return nil, ErrPasswordResetTokenNotFound
	}

	if len(newPassword) < 8 {
		return nil, ErrWeakPassword
	}

	if newPassword != confirmPassword {
		return nil, ErrNewPasswordMismatch
	}

	tokenHash := HashPasswordResetToken(
		rawToken,
	)

	resetToken, err :=
		s.repository.FindActivePasswordResetTokenByHash(
			ctx,
			tokenHash,
		)

	if err != nil {
		if errors.Is(
			err,
			ErrPasswordResetTokenNotFound,
		) {
			return nil, ErrPasswordResetTokenNotFound
		}

		return nil, fmt.Errorf(
			"failed to validate password reset token: %w",
			err,
		)
	}

	if time.Now().After(resetToken.ExpiresAt) {
		return nil, ErrPasswordResetExpired
	}

	if resetToken.UsedAt != nil {
		return nil, ErrPasswordResetAlreadyUsed
	}

	user, err := s.repository.FindUserByID(
		ctx,
		resetToken.UserID,
	)

	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}

		return nil, fmt.Errorf(
			"failed to retrieve password reset user: %w",
			err,
		)
	}

	if VerifyPassword(
		newPassword,
		user.PasswordHash,
	) {
		return nil, ErrNewPasswordSame
	}

	newPasswordHash, err :=
		bcrypt.GenerateFromPassword(
			[]byte(newPassword),
			bcrypt.DefaultCost,
		)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to hash reset password: %w",
			err,
		)
	}

	if err := s.repository.UpdatePassword(
		ctx,
		user.ID,
		user.OrganizationID,
		string(newPasswordHash),
	); err != nil {
		return nil, fmt.Errorf(
			"failed to reset password: %w",
			err,
		)
	}

	if err := s.repository.MarkPasswordResetTokenUsed(
		ctx,
		resetToken.ID,
	); err != nil {
		return nil, fmt.Errorf(
			"password reset but failed to mark token as used: %w",
			err,
		)
	}

	if err := s.repository.RevokePasswordResetTokensByUserID(
		ctx,
		user.ID,
	); err != nil {
		return nil, fmt.Errorf(
			"password reset but failed to revoke remaining reset tokens: %w",
			err,
		)
	}

	if err := s.repository.RevokeAllUserRefreshTokens(
		ctx,
		user.ID,
		"PASSWORD_RESET",
	); err != nil {
		return nil, fmt.Errorf(
			"password reset but failed to revoke refresh tokens: %w",
			err,
		)
	}

	if err := s.LogoutAllSessions(
		ctx,
		user.ID,
	); err != nil {
		return nil, fmt.Errorf(
			"password reset but failed to terminate sessions: %w",
			err,
		)
	}

	return &ResetPasswordResponse{
		PasswordReset:      true,
		SessionsTerminated: true,
		LoginRequired:      true,
	}, nil
}
