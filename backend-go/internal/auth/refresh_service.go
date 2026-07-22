package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrRefreshSessionMismatch = errors.New(
		"refresh token does not belong to the active session",
	)
)

// RefreshAccessToken validates the existing refresh token,
// rotates it, creates a new access token and refresh token,
// and updates the authentication session.
func (s *Service) RefreshAccessToken(
	ctx context.Context,
	request RefreshTokenRequest,
) (*RefreshTokenResponse, error) {
	rawRefreshToken := strings.TrimSpace(
		request.RefreshToken,
	)

	if rawRefreshToken == "" {
		return nil, ErrRefreshTokenNotFound
	}

	storedRefreshToken, err :=
		s.repository.ValidateRefreshToken(
			ctx,
			rawRefreshToken,
		)
	if err != nil {
		return nil, err
	}

	user, err := s.findUserByID(
		ctx,
		storedRefreshToken.UserID,
	)
	if err != nil {
		return nil, err
	}

	if err := s.validateAccountStatus(user); err != nil {
		return nil, err
	}

	if user.ID != storedRefreshToken.UserID {
		return nil, ErrRefreshSessionMismatch
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

	newAccessToken, accessTokenExpiresAt, err :=
		s.jwtManager.GenerateAccessToken(
			user,
			roles,
			storedRefreshToken.SessionID,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate refreshed access token: %w",
			err,
		)
	}

	newRefreshToken, err := GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate rotated refresh token: %w",
			err,
		)
	}

	tx, err := s.repository.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to begin refresh-token transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const lockOldRefreshTokenQuery = `
		SELECT id
		FROM refresh_tokens
		WHERE
			id = $1
			AND user_id = $2
			AND session_id = $3
			AND status = 'ACTIVE'
			AND revoked_at IS NULL
			AND expires_at > CURRENT_TIMESTAMP
		FOR UPDATE;
	`

	var lockedRefreshTokenID uuid.UUID

	err = tx.QueryRow(
		ctx,
		lockOldRefreshTokenQuery,
		storedRefreshToken.ID,
		user.ID,
		storedRefreshToken.SessionID,
	).Scan(&lockedRefreshTokenID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenInactive
		}

		return nil, fmt.Errorf(
			"failed to lock existing refresh token: %w",
			err,
		)
	}

	const insertNewRefreshTokenQuery = `
		INSERT INTO refresh_tokens (
			id,
			user_id,
			session_id,
			token_hash,
			issued_at,
			expires_at,
			status,
			created_at
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			CURRENT_TIMESTAMP,
			$5,
			'ACTIVE',
			CURRENT_TIMESTAMP
		);
	`

	_, err = tx.Exec(
		ctx,
		insertNewRefreshTokenQuery,
		newRefreshToken.ID,
		user.ID,
		storedRefreshToken.SessionID,
		hashSessionToken(newRefreshToken.Token),
		newRefreshToken.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to insert rotated refresh token: %w",
			err,
		)
	}

	const replaceOldRefreshTokenQuery = `
		UPDATE refresh_tokens
		SET
			status = 'REPLACED',
			last_used_at = CURRENT_TIMESTAMP,
			revoked_at = CURRENT_TIMESTAMP,
			replaced_by_token_id = $2,
			revocation_reason = 'TOKEN_ROTATED'
		WHERE
			id = $1
			AND status = 'ACTIVE'
			AND revoked_at IS NULL;
	`

	commandTag, err := tx.Exec(
		ctx,
		replaceOldRefreshTokenQuery,
		storedRefreshToken.ID,
		newRefreshToken.ID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to replace existing refresh token: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return nil, ErrRefreshTokenInactive
	}

	const updateSessionQuery = `
		UPDATE authentication_sessions
		SET
			session_token_hash = $4,
			expires_at = $5,
			status = 'ACTIVE',
			terminated_at = NULL,
			termination_reason = NULL,
			last_activity_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND user_id = $2
			AND organization_id = $3;
	`

	commandTag, err = tx.Exec(
		ctx,
		updateSessionQuery,
		storedRefreshToken.SessionID,
		user.ID,
		user.OrganizationID,
		hashSessionToken(newAccessToken),
		accessTokenExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to update authentication session: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return nil, ErrSessionNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"failed to commit refresh-token transaction: %w",
			err,
		)
	}

	expiresInSeconds := int64(
		time.Until(accessTokenExpiresAt).Seconds(),
	)

	if expiresInSeconds < 0 {
		expiresInSeconds = 0
	}

	return &RefreshTokenResponse{
		AccessToken:      newAccessToken,
		RefreshToken:     newRefreshToken.Token,
		TokenType:        "Bearer",
		ExpiresInSeconds: expiresInSeconds,
	}, nil
}

// RevokeRefreshToken revokes one refresh token.
func (s *Service) RevokeRefreshToken(
	ctx context.Context,
	request RevokeRefreshTokenRequest,
) error {
	rawRefreshToken := strings.TrimSpace(
		request.RefreshToken,
	)

	if rawRefreshToken == "" {
		return ErrRefreshTokenNotFound
	}

	storedRefreshToken, err :=
		s.repository.FindRefreshToken(
			ctx,
			rawRefreshToken,
		)
	if err != nil {
		return err
	}

	if err := s.repository.RevokeRefreshToken(
		ctx,
		storedRefreshToken.ID,
		"USER_REVOKED_TOKEN",
	); err != nil {
		return err
	}

	return nil
}

// LogoutAllSessions terminates every active authentication session
// and revokes every active refresh token belonging to the user.
func (s *Service) LogoutAllSessions(
	ctx context.Context,
	userID uuid.UUID,
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	tx, err := s.repository.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"failed to begin logout-all transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const revokeRefreshTokensQuery = `
		UPDATE refresh_tokens
		SET
			status = 'REVOKED',
			revoked_at = CURRENT_TIMESTAMP,
			revocation_reason = 'USER_LOGOUT_ALL_DEVICES'
		WHERE
			user_id = $1
			AND status = 'ACTIVE'
			AND revoked_at IS NULL;
	`

	_, err = tx.Exec(
		ctx,
		revokeRefreshTokensQuery,
		userID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to revoke user refresh tokens: %w",
			err,
		)
	}

	const terminateSessionsQuery = `
		UPDATE authentication_sessions
		SET
			status = 'TERMINATED',
			terminated_at = CURRENT_TIMESTAMP,
			termination_reason = 'USER_LOGOUT_ALL_DEVICES',
			last_activity_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			user_id = $1
			AND status = 'ACTIVE';
	`

	_, err = tx.Exec(
		ctx,
		terminateSessionsQuery,
		userID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to terminate user sessions: %w",
			err,
		)
	}

	const updateUserLogoutQuery = `
		UPDATE users
		SET
			last_logout_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND deleted_at IS NULL;
	`

	commandTag, err := tx.Exec(
		ctx,
		updateUserLogoutQuery,
		userID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to update user logout time: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"failed to commit logout-all transaction: %w",
			err,
		)
	}

	return nil
}

// findUserByID retrieves the complete user information
// required for generating a new access token.
func (s *Service) findUserByID(
	ctx context.Context,
	userID uuid.UUID,
) (*User, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}

	const query = `
		SELECT
			u.id,
			u.organization_id,
			u.username,
			u.official_email,
			u.password_hash,
			u.user_type,
			u.account_status,
			u.email_verified,
			u.phone_verified,
			u.mfa_enabled,
			u.must_change_password,
			u.failed_login_attempts,
			u.locked_until,
			u.password_changed_at,
			u.last_login_at,
			u.last_logout_at,
			u.preferred_language,
			u.timezone,
			u.created_at,
			u.updated_at,
			u.deleted_at
		FROM users u
		WHERE
			u.id = $1
			AND u.deleted_at IS NULL
		LIMIT 1;
	`

	var user User

	err := s.repository.db.QueryRow(
		ctx,
		query,
		userID,
	).Scan(
		&user.ID,
		&user.OrganizationID,
		&user.Username,
		&user.OfficialEmail,
		&user.PasswordHash,
		&user.UserType,
		&user.AccountStatus,
		&user.EmailVerified,
		&user.PhoneVerified,
		&user.MFAEnabled,
		&user.MustChangePassword,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.PasswordChangedAt,
		&user.LastLoginAt,
		&user.LastLogoutAt,
		&user.PreferredLanguage,
		&user.Timezone,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}

		return nil, fmt.Errorf(
			"failed to find user by ID: %w",
			err,
		)
	}

	return &user, nil
}
