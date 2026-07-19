package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidCredentials = errors.New("invalid username/email or password")
	ErrAccountPending     = errors.New("account activation is pending")
	ErrAccountInactive    = errors.New("account is inactive")
	ErrAccountSuspended   = errors.New("account is suspended")
	ErrAccountLocked      = errors.New("account is temporarily locked")
	ErrNoActiveRoles      = errors.New("user has no active roles")
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

		return nil, fmt.Errorf("failed to retrieve user: %w", err)
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

	accessToken, expiresAt, err :=
		s.jwtManager.GenerateAccessToken(user, roles)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate access token: %w",
			err,
		)
	}

	if err := s.repository.RecordSuccessfulLogin(
		ctx,
		user.ID,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to record successful login: %w",
			err,
		)
	}

	if strings.TrimSpace(displayName) == "" {
		displayName = user.Username
	}

	expiresInSeconds := int64(
		time.Until(expiresAt).Seconds(),
	)

	if expiresInSeconds < 0 {
		expiresInSeconds = 0
	}

	response := &LoginResponse{
		AccessToken:      accessToken,
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

		// Lock duration has expired.
		// Password verification may continue.

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
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if err := s.repository.UpdateLastLogout(
		ctx,
		userID,
	); err != nil {
		return fmt.Errorf(
			"failed to record logout: %w",
			err,
		)
	}

	return nil
}
