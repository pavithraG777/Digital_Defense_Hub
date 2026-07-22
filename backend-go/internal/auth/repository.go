package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUserNotFound               = errors.New("user not found")
	ErrSessionNotFound            = errors.New("authentication session not found")
	ErrSessionInactive            = errors.New("authentication session is not active")
	ErrSessionExpired             = errors.New("authentication session has expired")
	ErrSessionMismatch            = errors.New("authentication session does not belong to the user")
	ErrPasswordResetTokenNotFound = errors.New("password reset token is invalid or expired")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

// FindUserByIdentifier searches using username or official email.
func (r *Repository) FindUserByIdentifier(
	ctx context.Context,
	identifier string,
) (*User, string, error) {
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
			u.deleted_at,
			COALESCE(
				NULLIF(up.display_name, ''),
				TRIM(
					CONCAT_WS(
						' ',
						up.first_name,
						up.middle_name,
						up.last_name
					)
				),
				u.username
			) AS display_name
		FROM users u
		LEFT JOIN user_profiles up
			ON up.user_id = u.id
		WHERE
			u.deleted_at IS NULL
			AND (
				LOWER(u.username) = LOWER($1)
				OR LOWER(u.official_email) = LOWER($1)
			)
		LIMIT 1;
	`

	var user User
	var displayName string

	err := r.db.QueryRow(
		ctx,
		query,
		identifier,
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
		&displayName,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrUserNotFound
		}

		return nil, "", fmt.Errorf(
			"failed to find user by identifier: %w",
			err,
		)
	}

	return &user, displayName, nil
}

// FindUserByID retrieves one active, non-deleted user using the user ID.
func (r *Repository) FindUserByID(
	ctx context.Context,
	userID uuid.UUID,
) (*User, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}

	const query = `
		SELECT
			id,
			organization_id,
			username,
			official_email,
			password_hash,
			user_type,
			account_status,
			email_verified,
			phone_verified,
			mfa_enabled,
			must_change_password,
			failed_login_attempts,
			locked_until,
			password_changed_at,
			last_login_at,
			last_logout_at,
			preferred_language,
			timezone,
			created_at,
			updated_at,
			deleted_at
		FROM users
		WHERE
			id = $1
			AND deleted_at IS NULL
		LIMIT 1;
	`

	var user User

	err := r.db.QueryRow(
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

// UpdatePassword saves the new password hash and records the password
// change time. It also clears the forced password-change requirement.
func (r *Repository) UpdatePassword(
	ctx context.Context,
	userID uuid.UUID,
	organizationID uuid.UUID,
	passwordHash string,
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if organizationID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}

	if passwordHash == "" {
		return fmt.Errorf("password hash is required")
	}

	const query = `
		UPDATE users
		SET
			password_hash = $3,
			password_changed_at = CURRENT_TIMESTAMP,
			must_change_password = FALSE,
			failed_login_attempts = 0,
			locked_until = NULL,
			last_logout_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		userID,
		organizationID,
		passwordHash,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to update user password: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *Repository) CreatePasswordResetToken(
	ctx context.Context,
	token *PasswordResetToken,
) error {
	const query = `
		INSERT INTO password_reset_tokens (
			id,
			user_id,
			token_hash,
			requested_ip_address,
			requested_device,
			expires_at,
			status,
			created_at
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			CURRENT_TIMESTAMP
		);
	`

	_, err := r.db.Exec(
		ctx,
		query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.RequestedIPAddress,
		token.RequestedDevice,
		token.ExpiresAt,
		token.Status,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to create password reset token: %w",
			err,
		)
	}

	return nil
}

func (r *Repository) FindActivePasswordResetTokenByHash(
	ctx context.Context,
	tokenHash string,
) (*PasswordResetToken, error) {
	if tokenHash == "" {
		return nil, fmt.Errorf("password reset token hash is required")
	}

	const query = `
		SELECT
			id,
			user_id,
			token_hash,
			requested_ip_address,
			requested_device,
			expires_at,
			used_at,
			revoked_at,
			status,
			created_at
		FROM password_reset_tokens
		WHERE
			token_hash = $1
			AND status = 'ACTIVE'
			AND used_at IS NULL
			AND revoked_at IS NULL
			AND expires_at > CURRENT_TIMESTAMP
		LIMIT 1;
	`

	var token PasswordResetToken

	err := r.db.QueryRow(
		ctx,
		query,
		tokenHash,
	).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.RequestedIPAddress,
		&token.RequestedDevice,
		&token.ExpiresAt,
		&token.UsedAt,
		&token.RevokedAt,
		&token.Status,
		&token.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPasswordResetTokenNotFound
		}

		return nil, fmt.Errorf(
			"failed to find active password reset token: %w",
			err,
		)
	}

	return &token, nil
}

func (r *Repository) MarkPasswordResetTokenUsed(
	ctx context.Context,
	id uuid.UUID,
) error {
	if id == uuid.Nil {
		return fmt.Errorf("password reset token ID is required")
	}

	const query = `
		UPDATE password_reset_tokens
		SET
			used_at = CURRENT_TIMESTAMP,
			status = 'USED'
		WHERE
			id = $1
			AND status = 'ACTIVE';
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		id,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to mark password reset token as used: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrPasswordResetTokenNotFound
	}

	return nil
}

func (r *Repository) RevokePasswordResetTokensByUserID(
	ctx context.Context,
	userID uuid.UUID,
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	const query = `
		UPDATE password_reset_tokens
		SET
			revoked_at = CURRENT_TIMESTAMP,
			status = 'REVOKED'
		WHERE
			user_id = $1
			AND status = 'ACTIVE'
			AND used_at IS NULL
			AND revoked_at IS NULL;
	`

	_, err := r.db.Exec(
		ctx,
		query,
		userID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to revoke password reset tokens: %w",
			err,
		)
	}

	return nil
}

// GetActiveRoleCodes returns active roles assigned to the user.
func (r *Repository) GetActiveRoleCodes(
	ctx context.Context,
	userID uuid.UUID,
) ([]string, error) {
	const query = `
		SELECT r.role_code
		FROM user_roles ur
		INNER JOIN roles r
			ON r.id = ur.role_id
		WHERE
			ur.user_id = $1
			AND ur.status = 'ACTIVE'
			AND ur.is_active = TRUE
			AND r.status = 'ACTIVE'
			AND r.deleted_at IS NULL
			AND ur.valid_from <= CURRENT_TIMESTAMP
			AND (
				ur.expires_at IS NULL
				OR ur.expires_at > CURRENT_TIMESTAMP
			)
		ORDER BY
			ur.is_primary DESC,
			r.priority_level ASC,
			r.role_code ASC;
	`

	rows, err := r.db.Query(
		ctx,
		query,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to fetch user roles: %w",
			err,
		)
	}
	defer rows.Close()

	roles := make([]string, 0)

	for rows.Next() {
		var roleCode string

		if err := rows.Scan(&roleCode); err != nil {
			return nil, fmt.Errorf(
				"failed to scan user role: %w",
				err,
			)
		}

		roles = append(
			roles,
			roleCode,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"failed while reading user roles: %w",
			err,
		)
	}

	return roles, nil
}

// IncrementFailedLogin increases the failed login count.
func (r *Repository) IncrementFailedLogin(
	ctx context.Context,
	userID uuid.UUID,
) error {
	const query = `
		UPDATE users
		SET
			failed_login_attempts = failed_login_attempts + 1,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		userID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to increment login attempts: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

// LockUser temporarily locks an account.
func (r *Repository) LockUser(
	ctx context.Context,
	userID uuid.UUID,
	lockedUntil time.Time,
) error {
	const query = `
		UPDATE users
		SET
			account_status = 'LOCKED',
			locked_until = $2,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		userID,
		lockedUntil,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to lock user account: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

// RecordSuccessfulLogin resets failures and updates login time.
func (r *Repository) RecordSuccessfulLogin(
	ctx context.Context,
	userID uuid.UUID,
) error {
	const query = `
		UPDATE users
		SET
			failed_login_attempts = 0,
			locked_until = NULL,
			account_status = CASE
				WHEN account_status = 'LOCKED' THEN 'ACTIVE'
				ELSE account_status
			END,
			last_login_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		userID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to record successful login: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

// UpdateLastLogout records the user's logout time.
func (r *Repository) UpdateLastLogout(
	ctx context.Context,
	userID uuid.UUID,
) error {
	const query = `
		UPDATE users
		SET
			last_logout_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		userID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to update last logout time: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *Repository) TerminateSession(
	ctx context.Context,
	sessionID uuid.UUID,
	userID uuid.UUID,
	organizationID uuid.UUID,
	reason string,
) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if organizationID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}

	if reason == "" {
		reason = "USER_LOGOUT"
	}

	const query = `
		UPDATE authentication_sessions
		SET
			status = 'TERMINATED',
			terminated_at = CURRENT_TIMESTAMP,
			termination_reason = $4,
			last_activity_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND user_id = $2
			AND organization_id = $3
			AND status = 'ACTIVE';
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		sessionID,
		userID,
		organizationID,
		reason,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to terminate authentication session: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *Repository) CreateSession(
	ctx context.Context,
	sessionID uuid.UUID,
	userID uuid.UUID,
	organizationID uuid.UUID,
	accessToken string,
	expiresAt time.Time,
) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if organizationID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}

	if accessToken == "" {
		return fmt.Errorf("access token is required")
	}

	if expiresAt.IsZero() {
		return fmt.Errorf(
			"session expiry time is required",
		)
	}

	tokenHash := hashSessionToken(
		accessToken,
	)

	const query = `
		INSERT INTO authentication_sessions (
			id,
			user_id,
			organization_id,
			session_token_hash,
			expires_at,
			status,
			mfa_verified,
			login_at,
			last_activity_at,
			created_at,
			updated_at
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			'ACTIVE',
			FALSE,
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP
		);
	`

	_, err := r.db.Exec(
		ctx,
		query,
		sessionID,
		userID,
		organizationID,
		tokenHash,
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create authentication session: %w",
			err,
		)
	}

	fmt.Println("INSERT SUCCESS")
	fmt.Println("Session ID:", sessionID)

	return nil
}

func hashSessionToken(
	token string,
) string {
	hash := sha256.Sum256(
		[]byte(token),
	)

	return hex.EncodeToString(
		hash[:],
	)
}

// ValidateSession verifies that the session exists, belongs to the
// authenticated user and organization, is active, and has not expired.
func (r *Repository) ValidateSession(
	ctx context.Context,
	sessionID uuid.UUID,
	userID uuid.UUID,
	organizationID uuid.UUID,
) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if organizationID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}

	const query = `
		SELECT
			user_id,
			organization_id,
			status,
			expires_at
		FROM authentication_sessions
		WHERE id = $1
		LIMIT 1;
	`

	var storedUserID uuid.UUID
	var storedOrganizationID uuid.UUID
	var status string
	var expiresAt time.Time

	err := r.db.QueryRow(
		ctx,
		query,
		sessionID,
	).Scan(
		&storedUserID,
		&storedOrganizationID,
		&status,
		&expiresAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSessionNotFound
		}

		return fmt.Errorf(
			"failed to validate authentication session: %w",
			err,
		)
	}

	if storedUserID != userID ||
		storedOrganizationID != organizationID {
		return ErrSessionMismatch
	}

	if time.Now().After(expiresAt) {
		if err := r.MarkSessionExpired(
			ctx,
			sessionID,
		); err != nil {
			return fmt.Errorf(
				"failed to mark session as expired: %w",
				err,
			)
		}

		return ErrSessionExpired
	}

	if status != "ACTIVE" {
		return ErrSessionInactive
	}

	return nil
}

// MarkSessionExpired changes an expired active session to EXPIRED.
func (r *Repository) MarkSessionExpired(
	ctx context.Context,
	sessionID uuid.UUID,
) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	const query = `
		UPDATE authentication_sessions
		SET
			status = 'EXPIRED',
			terminated_at = COALESCE(
				terminated_at,
				CURRENT_TIMESTAMP
			),
			termination_reason = COALESCE(
				termination_reason,
				'TOKEN_EXPIRED'
			),
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND status = 'ACTIVE';
	`

	_, err := r.db.Exec(
		ctx,
		query,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to mark authentication session as expired: %w",
			err,
		)
	}

	return nil
}

// UpdateSessionActivity records the latest authenticated request time.
func (r *Repository) UpdateSessionActivity(
	ctx context.Context,
	sessionID uuid.UUID,
	userID uuid.UUID,
	organizationID uuid.UUID,
) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if organizationID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}

	const query = `
		UPDATE authentication_sessions
		SET
			last_activity_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND user_id = $2
			AND organization_id = $3
			AND status = 'ACTIVE'
			AND expires_at > CURRENT_TIMESTAMP;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		sessionID,
		userID,
		organizationID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to update session activity: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrSessionInactive
	}

	return nil
}

// LogoutSession terminates the current session and records the user logout time.
// Both database updates are executed inside one transaction.
func (r *Repository) LogoutSession(
	ctx context.Context,
	sessionID uuid.UUID,
	userID uuid.UUID,
	organizationID uuid.UUID,
) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("session ID is required")
	}

	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if organizationID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"failed to begin logout transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const terminateSessionQuery = `
		UPDATE authentication_sessions
		SET
			status = 'TERMINATED',
			terminated_at = CURRENT_TIMESTAMP,
			termination_reason = 'USER_LOGOUT',
			last_activity_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND user_id = $2
			AND organization_id = $3
			AND status = 'ACTIVE'
			AND expires_at > CURRENT_TIMESTAMP;
	`

	commandTag, err := tx.Exec(
		ctx,
		terminateSessionQuery,
		sessionID,
		userID,
		organizationID,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to terminate authentication session: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrSessionInactive
	}

	const updateUserLogoutQuery = `
		UPDATE users
		SET
			last_logout_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL;
	`

	commandTag, err = tx.Exec(
		ctx,
		updateUserLogoutQuery,
		userID,
		organizationID,
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
			"failed to commit logout transaction: %w",
			err,
		)
	}

	return nil
}
