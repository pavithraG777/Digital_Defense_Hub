package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrBootstrapAlreadyCompleted = errors.New(
		"bootstrap has already been completed",
	)
)

type BootstrapRequest struct {
	OrganizationCode string `json:"organization_code" binding:"required,min=2,max=50"`
	OrganizationName string `json:"organization_name" binding:"required,min=2,max=150"`
	Username         string `json:"username" binding:"required,min=3,max=50"`
	OfficialEmail    string `json:"official_email" binding:"required,email"`
	Password         string `json:"password" binding:"required,min=8"`
	FirstName        string `json:"first_name" binding:"required,min=2,max=100"`
	LastName         string `json:"last_name" binding:"omitempty,max=100"`
}

type BootstrapResponse struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	UserID         uuid.UUID `json:"user_id"`
	RoleID         uuid.UUID `json:"role_id"`
	Username       string    `json:"username"`
	OfficialEmail  string    `json:"official_email"`
}

func (s *Service) BootstrapAdmin(
	ctx context.Context,
	request BootstrapRequest,
) (*BootstrapResponse, error) {
	request.OrganizationCode = strings.ToUpper(
		strings.TrimSpace(request.OrganizationCode),
	)
	request.OrganizationName = strings.TrimSpace(
		request.OrganizationName,
	)
	request.Username = strings.ToLower(
		strings.TrimSpace(request.Username),
	)
	request.OfficialEmail = strings.ToLower(
		strings.TrimSpace(request.OfficialEmail),
	)
	request.FirstName = strings.TrimSpace(request.FirstName)
	request.LastName = strings.TrimSpace(request.LastName)

	passwordHash, err := HashPassword(request.Password)
	if err != nil {
		return nil, err
	}

	tx, err := s.repository.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to begin bootstrap transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Prevent two bootstrap requests from running simultaneously.
	if _, err := tx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(82736491);`,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to obtain bootstrap lock: %w",
			err,
		)
	}

	bootstrapCompleted, err := hasExistingUsers(ctx, tx)
	if err != nil {
		return nil, err
	}

	if bootstrapCompleted {
		return nil, ErrBootstrapAlreadyCompleted
	}

	organizationID, err := createBootstrapOrganization(
		ctx,
		tx,
		request,
	)
	if err != nil {
		return nil, err
	}

	roleID, err := createBootstrapAdminRole(
		ctx,
		tx,
		organizationID,
	)
	if err != nil {
		return nil, err
	}

	userID, err := createBootstrapAdminUser(
		ctx,
		tx,
		organizationID,
		request,
		passwordHash,
	)
	if err != nil {
		return nil, err
	}

	if err := createBootstrapUserProfile(
		ctx,
		tx,
		userID,
		request,
	); err != nil {
		return nil, err
	}

	if err := assignBootstrapAdminRole(
		ctx,
		tx,
		userID,
		roleID,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"failed to commit bootstrap transaction: %w",
			err,
		)
	}

	return &BootstrapResponse{
		OrganizationID: organizationID,
		UserID:         userID,
		RoleID:         roleID,
		Username:       request.Username,
		OfficialEmail:  request.OfficialEmail,
	}, nil
}

func hasExistingUsers(
	ctx context.Context,
	tx pgx.Tx,
) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE deleted_at IS NULL
		);
	`

	var exists bool

	if err := tx.QueryRow(ctx, query).Scan(&exists); err != nil {
		return false, fmt.Errorf(
			"failed to check bootstrap status: %w",
			err,
		)
	}

	return exists, nil
}

func createBootstrapOrganization(
	ctx context.Context,
	tx pgx.Tx,
	request BootstrapRequest,
) (uuid.UUID, error) {
	query := `
		INSERT INTO organizations (
			organization_code,
			legal_name,
			display_name,
			organization_type,
			description,
			country_of_registration,
			primary_email,
			security_email,
			sector,
			industry,
			critical_infrastructure,
			data_sensitivity_level,
			deployment_mode,
			timezone,
			default_language,
			data_retention_days,
			status,
			approved_at
		)
		VALUES (
			$1,
			$2,
			$2,
			'EDUCATIONAL',
			'Primary organization created during system bootstrap',
			'India',
			$3,
			$3,
			'EDUCATION',
			'CYBER_SECURITY',
			FALSE,
			'CONFIDENTIAL',
			'OFFLINE',
			'Asia/Kolkata',
			'ENGLISH',
			365,
			'ACTIVE',
			CURRENT_TIMESTAMP
		)
		RETURNING id;
	`

	var organizationID uuid.UUID

	err := tx.QueryRow(
		ctx,
		query,
		request.OrganizationCode,
		request.OrganizationName,
		request.OfficialEmail,
	).Scan(&organizationID)

	if err != nil {
		return uuid.Nil, fmt.Errorf(
			"failed to create bootstrap organization: %w",
			err,
		)
	}

	return organizationID, nil
}

func createBootstrapAdminRole(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
) (uuid.UUID, error) {
	query := `
		INSERT INTO roles (
			organization_id,
			role_code,
			role_name,
			description,
			role_scope,
			is_system_role,
			priority_level,
			status
		)
		VALUES (
			$1,
			'SUPER_ADMIN',
			'Super Administrator',
			'Primary system administrator with full platform access',
			'ORGANIZATION',
			TRUE,
			1,
			'ACTIVE'
		)
		RETURNING id;
	`

	var roleID uuid.UUID

	if err := tx.QueryRow(
		ctx,
		query,
		organizationID,
	).Scan(&roleID); err != nil {
		return uuid.Nil, fmt.Errorf(
			"failed to create bootstrap admin role: %w",
			err,
		)
	}

	return roleID, nil
}

func createBootstrapAdminUser(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	request BootstrapRequest,
	passwordHash string,
) (uuid.UUID, error) {
	query := `
		INSERT INTO users (
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
			password_changed_at,
			preferred_language,
			timezone
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			'INTERNAL',
			'ACTIVE',
			TRUE,
			FALSE,
			FALSE,
			TRUE,
			0,
			CURRENT_TIMESTAMP,
			'ENGLISH',
			'Asia/Kolkata'
		)
		RETURNING id;
	`

	var userID uuid.UUID

	if err := tx.QueryRow(
		ctx,
		query,
		organizationID,
		request.Username,
		request.OfficialEmail,
		passwordHash,
	).Scan(&userID); err != nil {
		return uuid.Nil, fmt.Errorf(
			"failed to create bootstrap admin user: %w",
			err,
		)
	}

	return userID, nil
}

func createBootstrapUserProfile(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	request BootstrapRequest,
) error {
	query := `
		INSERT INTO user_profiles (
			user_id,
			employee_code,
			first_name,
			last_name,
			display_name,
			designation,
			employment_type,
			security_clearance_level
		)
		VALUES (
			$1,
			'ADMIN-001',
			$2,
			NULLIF($3, ''),
			TRIM(CONCAT_WS(' ', $2, NULLIF($3, ''))),
			'System Administrator',
			'PERMANENT',
			'RESTRICTED'
		);
	`

	if _, err := tx.Exec(
		ctx,
		query,
		userID,
		request.FirstName,
		request.LastName,
	); err != nil {
		return fmt.Errorf(
			"failed to create bootstrap user profile: %w",
			err,
		)
	}

	return nil
}

func assignBootstrapAdminRole(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	roleID uuid.UUID,
) error {
	query := `
		INSERT INTO user_roles (
			user_id,
			role_id,
			assigned_by,
			assignment_reason,
			valid_from,
			is_primary,
			status
		)
		VALUES (
			$1,
			$2,
			$1,
			'Initial system bootstrap administrator',
			CURRENT_TIMESTAMP,
			TRUE,
			'ACTIVE'
		);
	`

	if _, err := tx.Exec(
		ctx,
		query,
		userID,
		roleID,
	); err != nil {
		return fmt.Errorf(
			"failed to assign bootstrap admin role: %w",
			err,
		)
	}

	return nil
}
