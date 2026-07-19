package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUserNotFound = errors.New("user not found")

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

	query := `
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

	err := r.db.QueryRow(ctx, query, identifier).Scan(
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

// GetActiveRoleCodes returns active roles assigned to the user.
func (r *Repository) GetActiveRoleCodes(
	ctx context.Context,
	userID uuid.UUID,
) ([]string, error) {

	query := `
		SELECT r.role_code
		FROM user_roles ur
		INNER JOIN roles r
			ON r.id = ur.role_id
		WHERE
			ur.user_id = $1
			AND ur.status = 'ACTIVE'
			AND r.status = 'ACTIVE'
			AND r.deleted_at IS NULL
			AND ur.valid_from <= CURRENT_TIMESTAMP
			AND (
				ur.valid_until IS NULL
				OR ur.valid_until > CURRENT_TIMESTAMP
			)
		ORDER BY
			ur.is_primary DESC,
			r.priority_level ASC,
			r.role_code ASC;
	`

	rows, err := r.db.Query(ctx, query, userID)
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

		roles = append(roles, roleCode)
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

	query := `
		UPDATE users
		SET
			failed_login_attempts = failed_login_attempts + 1,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1;
	`

	commandTag, err := r.db.Exec(ctx, query, userID)
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

	query := `
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
		return fmt.Errorf("failed to lock user account: %w", err)
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

	query := `
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

	commandTag, err := r.db.Exec(ctx, query, userID)
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

	query := `
		UPDATE users
		SET
			last_logout_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1;
	`

	commandTag, err := r.db.Exec(ctx, query, userID)
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
