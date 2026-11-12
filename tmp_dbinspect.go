package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	dsn := "postgres://postgres:pavi072007@localhost:5432/offline_cyber_platform?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	rows, err := db.Query(ctx, `SELECT o.organization_code, o.legal_name, u.username, u.official_email, u.account_status, u.organization_id FROM users u JOIN organizations o ON o.id=u.organization_id WHERE u.deleted_at IS NULL ORDER BY o.organization_code, u.username LIMIT 20`)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	for rows.Next() {
		var code, legal, username, email, status, orgID string
		if err := rows.Scan(&code, &legal, &username, &email, &status, &orgID); err != nil {
			panic(err)
		}
		fmt.Printf("%s | %s | %s | %s | %s | %s\n", code, legal, username, email, status, orgID)
	}
	if err := rows.Err(); err != nil {
		panic(err)
	}
}
