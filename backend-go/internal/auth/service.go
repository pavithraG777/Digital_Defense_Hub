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

	ErrPasswordResetAlreadyUsed = errors.New("password reset token has already been used")
)

const (
	maxFailedLoginAttempts = 5
	accountLockDuration    = 15 * time.Minute
)

type Service struct {
	repository *Repository
	jwtManager *JWTManager
}

func NewService(
	repository *Repository,
	jwtManager *JWTManager,
) *Service {
	return &Service{
		repository: repository,
		jwtManager: jwtManager,
	}
}

func (s *Service) Login(
	ctx context.Context,
	request LoginRequest,
) (*LoginResponse, error) {
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
