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
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer conn.Close(ctx)

	fmt.Println("=== roles for testuser ===")
	rows, err := conn.Query(ctx, `
        SELECT u.id, u.username, u.organization_id, u.account_status, u.deleted_at
        FROM users u
        WHERE u.username = 'testuser'
        AND u.deleted_at IS NULL
    `)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, username, orgID, accountStatus string
		var deletedAt *time.Time
		if err := rows.Scan(&id, &username, &orgID, &accountStatus, &deletedAt); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("user: %s %s org=%s status=%s deletedAt=%v\n", id, username, orgID, accountStatus, deletedAt)
	}

	fmt.Println("=== user_roles for testuser ===")
	rows, err = conn.Query(ctx, `
        SELECT ur.user_id, ur.role_id, ur.granted_by, ur.assignment_reason, ur.granted_at, ur.valid_from, ur.expires_at, ur.is_primary, ur.status, ur.is_active
        FROM user_roles ur
        JOIN users u ON u.id = ur.user_id
        WHERE u.username = 'testuser'
        ORDER BY ur.granted_at DESC
    `)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var userID, roleID, assignmentReason, status string
		var grantedBy *string
		var grantedAt, validFrom time.Time
		var expiresAt *time.Time
		var isPrimary *bool
		var isActive bool
		if err := rows.Scan(&userID, &roleID, &grantedBy, &assignmentReason, &grantedAt, &validFrom, &expiresAt, &isPrimary, &status, &isActive); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("ur: user=%s role=%s grantedBy=%v reason=%s grantedAt=%s from=%s expires=%v primary=%v status=%s active=%v\n", userID, roleID, grantedBy, assignmentReason, grantedAt, validFrom, expiresAt, isPrimary, status, isActive)
	}

	fmt.Println("=== active role codes using login query ===")
	rows, err = conn.Query(ctx, `
        SELECT r.role_code
        FROM user_roles ur
        INNER JOIN roles r ON r.id = ur.role_id
        JOIN users u ON u.id = ur.user_id
        WHERE u.username = 'testuser'
            AND ur.status = 'ACTIVE'
            AND ur.is_active = TRUE
            AND r.status = 'ACTIVE'
            AND r.deleted_at IS NULL
            AND ur.valid_from <= CURRENT_TIMESTAMP
            AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
        ORDER BY ur.is_primary DESC, r.priority_level ASC, r.role_code ASC
    `)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var roleCode string
		if err := rows.Scan(&roleCode); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("active role: %s\n", roleCode)
	}

	fmt.Println("=== roles metadata ===")
	rows, err = conn.Query(ctx, `
        SELECT r.id, r.role_code, r.role_name, r.status, r.deleted_at, r.organization_id
        FROM roles r
        WHERE r.role_code IN ('SUPER_ADMIN')
    `)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, roleCode, roleName, status, orgID string
		var deletedAt *time.Time
		if err := rows.Scan(&id, &roleCode, &roleName, &status, &deletedAt, &orgID); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("role: id=%s code=%s name=%s status=%s deletedAt=%v org=%s\n", id, roleCode, roleName, status, deletedAt, orgID)
	}
}
