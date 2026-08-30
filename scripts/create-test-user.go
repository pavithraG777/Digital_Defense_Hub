package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, "postgres://postgres:pavi072007@localhost:5432/offline_cyber_platform")
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer conn.Close(ctx)

	// Get organization ID
	var orgID string
	err = conn.QueryRow(ctx, "SELECT id FROM organizations WHERE organization_code = $1 AND deleted_at IS NULL", "CSL001").Scan(&orgID)
	if err != nil {
		log.Fatalf("Unable to find organization: %v\n", err)
	}

	// Insert test user
	query := `
	INSERT INTO users (
		id, organization_id, username, official_email, password_hash,
		user_type, account_status, email_verified, phone_verified, mfa_enabled,
		must_change_password, failed_login_attempts, password_changed_at,
		preferred_language, timezone, created_at, updated_at, deleted_at
	)
	VALUES (
		gen_random_uuid(), $1, $2, $3, $4,
		'INTERNAL', 'ACTIVE', TRUE, FALSE, FALSE,
		FALSE, 0, NOW(),
		'en', 'Asia/Kolkata', NOW(), NOW(), NULL
	)
	ON CONFLICT DO NOTHING
	`

	_, err = conn.Exec(ctx, query,
		orgID,
		"testuser",
		"testuser@cyberlab.local",
		"$2a$10$JQLaXP..MXYTku9eAB7tRehgMihk2PoTDINQ1jx.vaajj2yk22F3e", // Test1234!@#
	)

	if err != nil {
		log.Fatalf("Unable to insert user: %v\n", err)
	}

	var roleID string
	err = conn.QueryRow(ctx, `
		SELECT r.id
		FROM roles r
		JOIN organizations o
			ON o.id = r.organization_id
		WHERE o.organization_code = $1
		AND r.role_code = 'SUPER_ADMIN'
		AND r.deleted_at IS NULL
	`, "CSL001").Scan(&roleID)
	if err != nil {
		log.Fatalf("Unable to find SUPER_ADMIN role: %v\n", err)
	}

	_, err = conn.Exec(ctx, `
		INSERT INTO user_roles (
			user_id,
			role_id,
			granted_by,
			assignment_reason,
			granted_at,
			valid_from,
			expires_at,
			is_primary,
			status,
			is_active
		)
		SELECT
			u.id,
			$1,
			NULL,
			'Default SUPER_ADMIN role assigned for local test user',
			timezone('UTC', CURRENT_TIMESTAMP),
			timezone('UTC', CURRENT_TIMESTAMP),
			NULL,
			TRUE,
			'ACTIVE',
			TRUE
		FROM users u
		WHERE u.organization_id = $2
		AND u.username = 'testuser'
		AND u.deleted_at IS NULL
		AND NOT EXISTS (
			SELECT 1
			FROM user_roles ur
			WHERE ur.user_id = u.id
			AND ur.role_id = $1
			AND ur.status = 'ACTIVE'
		)
	`, roleID, orgID)
	if err != nil {
		log.Fatalf("Unable to assign SUPER_ADMIN role: %v\n", err)
	}

	fmt.Println("Test user created and assigned SUPER_ADMIN successfully!")
	fmt.Println("Username: testuser")
	fmt.Println("Password: Test1234!@#")
	fmt.Println("Email: testuser@cyberlab.local")
}
