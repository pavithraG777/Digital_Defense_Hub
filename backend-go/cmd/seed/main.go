package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/database"
)

const (
	organizationCode = "DDH001"
	organizationName = "Digital Defense Hub"
	organizationType = "RESEARCH_EDUCATION"

	adminUsername  = "admin"
	adminEmail     = "admin@digitaldefensehub.local"
	adminPassword  = "Admin@123"
	adminFirstName = "System"
	adminLastName  = "Administrator"

	adminRoleCode = "SUPER_ADMIN"
	adminRoleName = "Super Administrator"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	defer func() {
		_ = logger.Sync()
	}()

	db, err := database.Connect(cfg, logger)
	if err != nil {
		logger.Fatal(
			"Database connection failed",
			zap.Error(err),
		)
	}
	defer db.Close(logger)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	if err := seedAdministrator(ctx, db); err != nil {
		if errors.Is(err, errSeederAlreadyCompleted) {
			logger.Info(
				"Admin seeder has already been completed",
			)
			return
		}

		logger.Fatal(
			"Admin seeding failed",
			zap.Error(err),
		)
	}

	logger.Info(
		"Initial administrator created successfully",
		zap.String("username", adminUsername),
		zap.String("official_email", adminEmail),
	)

	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("Digital Defense Hub Admin Created")
	fmt.Println("==========================================")
	fmt.Println("Username :", adminUsername)
	fmt.Println("Email    :", adminEmail)
	fmt.Println("Password :", adminPassword)
	fmt.Println("==========================================")
	fmt.Println("Change this password after the first login.")
}

var errSeederAlreadyCompleted = errors.New(
	"initial administrator already exists",
)

func seedAdministrator(
	ctx context.Context,
	db *database.Database,
) error {
	passwordHash, err := auth.HashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("failed to hash administrator password: %w", err)
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin seed transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Prevent multiple seed processes from running simultaneously.
	if _, err := tx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(82736491);`,
	); err != nil {
		return fmt.Errorf("failed to acquire seed lock: %w", err)
	}

	exists, err := administratorExists(ctx, tx)
	if err != nil {
		return err
	}

	if exists {
		return errSeederAlreadyCompleted
	}

	organizationID, err := createOrganization(ctx, tx)
	if err != nil {
		return err
	}

	roleID, err := createAdminRole(
		ctx,
		tx,
		organizationID,
	)
	if err != nil {
		return err
	}

	userID, err := createAdminUser(
		ctx,
		tx,
		organizationID,
		passwordHash,
	)
	if err != nil {
		return err
	}

	if err := createAdminProfile(
		ctx,
		tx,
		userID,
	); err != nil {
		return err
	}

	if err := assignAdminRole(
		ctx,
		tx,
		userID,
		roleID,
	); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit seed transaction: %w", err)
	}

	return nil
}

func administratorExists(
	ctx context.Context,
	tx pgx.Tx,
) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE
				deleted_at IS NULL
				AND (
					LOWER(username) = LOWER($1)
					OR LOWER(official_email) = LOWER($2)
				)
		);
	`

	var exists bool

	if err := tx.QueryRow(
		ctx,
		query,
		adminUsername,
		adminEmail,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf(
			"failed to check existing administrator: %w",
			err,
		)
	}

	return exists, nil
}

func createOrganization(
	ctx context.Context,
	tx pgx.Tx,
) (uuid.UUID, error) {
	query := `
		INSERT INTO public.organizations (
			organization_code,
			legal_name,
			display_name,
			organization_type,
			description,
			primary_email,
			security_email,
			sector,
			industry,
			critical_infrastructure,
			data_sensitivity_level,
			deployment_mode,
			status,
			approved_at
		)
		VALUES (
			$1,
			$2,
			$2,
			'RESEARCH_EDUCATION',
			'Primary organization for Digital Defense Hub',
			$3,
			$3,
			'EDUCATION',
			'CYBER_SECURITY',
			FALSE,
			'CONFIDENTIAL',
			'OFFLINE',
			'ACTIVE',
			CURRENT_TIMESTAMP
		)
		RETURNING id;
	`

	var organizationID uuid.UUID

	fmt.Println("Creating organization with type: RESEARCH_EDUCATION")

	if err := tx.QueryRow(
		ctx,
		query,
		organizationCode,
		organizationName,
		adminEmail,
	).Scan(&organizationID); err != nil {
		return uuid.Nil, fmt.Errorf(
			"failed to create organization: %w",
			err,
		)
	}

	return organizationID, nil
}

func createAdminRole(
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
			$2,
			$3,
			'Primary administrator with full platform access',
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
		adminRoleCode,
		adminRoleName,
	).Scan(&roleID); err != nil {
		return uuid.Nil, fmt.Errorf(
			"failed to create administrator role: %w",
			err,
		)
	}

	return roleID, nil
}

func createAdminUser(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
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
		adminUsername,
		adminEmail,
		passwordHash,
	).Scan(&userID); err != nil {
		return uuid.Nil, fmt.Errorf(
			"failed to create administrator user: %w",
			err,
		)
	}

	return userID, nil
}

func createAdminProfile(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
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
			$3,
			$4,
			'System Administrator',
			'PERMANENT',
			'RESTRICTED'
		);
	`

	displayName := adminFirstName + " " + adminLastName

	if _, err := tx.Exec(
		ctx,
		query,
		userID,
		adminFirstName,
		adminLastName,
		displayName,
	); err != nil {
		return fmt.Errorf(
			"failed to create administrator profile: %w",
			err,
		)
	}

	return nil
}

func assignAdminRole(
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
			'Initial system administrator assignment',
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
			"failed to assign administrator role: %w",
			err,
		)
	}

	return nil
}
