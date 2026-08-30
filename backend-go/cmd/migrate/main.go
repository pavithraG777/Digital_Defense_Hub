package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/database"
	"go.uber.org/zap"
)

var migrationName = regexp.MustCompile(`^\d{3}_[a-z0-9_]+\.sql$`)

type migration struct{ name, path, checksum, sql string }

func main() {
	directory := flag.String("dir", "../scripts/migrations/seed", "numbered migration directory")
	validateOnly := flag.Bool("validate-only", false, "validate files without connecting to PostgreSQL")
	from := flag.Int("from", 0, "apply only migrations with this numeric prefix or newer")
	removeTestUser := flag.Bool("remove-insecure-test-user", false, "disable the legacy known-password test account")
	flag.Parse()
	migrations, err := loadMigrations(*directory)
	if err != nil {
		log.Fatal(err)
	}
	if err = requireRange(migrations, 24, 30); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Validated %d ordered migrations, including 024-030.\n", len(migrations))
	if *validateOnly {
		return
	}
	if *from > 0 {
		migrations = fromNumber(migrations, *from)
		if len(migrations) == 0 {
			log.Fatalf("no migrations found at or after %03d", *from)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}
	logger := zap.NewNop()
	db, err := database.Connect(cfg, logger)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer db.Close(logger)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if *removeTestUser {
		if err = disableKnownTestUser(ctx, db.Pool); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Legacy known-password test account disabled and test-seed history removed.")
		return
	}
	if err = apply(ctx, db.Pool, migrations); err != nil {
		log.Fatal(err)
	}
}

func fromNumber(items []migration, minimum int) []migration {
	prefix := fmt.Sprintf("%03d_", minimum)
	index := sort.Search(len(items), func(i int) bool { return items[i].name >= prefix })
	return items[index:]
}

func loadMigrations(directory string) ([]migration, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read migration directory: %w", err)
	}
	items := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !migrationName.MatchString(entry.Name()) || entry.Name() >= "900_" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), readErr)
		}
		if len(body) == 0 {
			return nil, fmt.Errorf("migration %s is empty", entry.Name())
		}
		digest := sha256.Sum256(body)
		items = append(items, migration{name: entry.Name(), path: path, checksum: hex.EncodeToString(digest[:]), sql: string(body)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	if len(items) == 0 {
		return nil, fmt.Errorf("no numbered migrations found in %s", directory)
	}
	return items, nil
}

func disableKnownTestUser(ctx context.Context, db *pgxpool.Pool) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `UPDATE users SET account_status='DISABLED',password_hash='$2a$10$invaliddisabledcredentialhash000000000000000000000000000',deleted_at=COALESCE(deleted_at,NOW()),updated_at=NOW() WHERE username='testuser' AND official_email='testuser@cyberlab.local'`)
	if err == nil {
		_, err = tx.Exec(ctx, `DELETE FROM platform_schema_migrations WHERE name='999_seed_test_user.sql'`)
	}
	if err != nil {
		return fmt.Errorf("disable known test user: %w", err)
	}
	return tx.Commit(ctx)
}

func requireRange(items []migration, first, last int) error {
	for number := first; number <= last; number++ {
		prefix := fmt.Sprintf("%03d_", number)
		found := false
		for _, item := range items {
			if len(item.name) >= 4 && item.name[:4] == prefix {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("required migration %03d is missing", number)
		}
	}
	return nil
}

func apply(ctx context.Context, db *pgxpool.Pool, items []migration) error {
	if _, err := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS platform_schema_migrations(name TEXT PRIMARY KEY,sha256 TEXT NOT NULL,applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`); err != nil {
		return fmt.Errorf("initialize migration history: %w", err)
	}
	if _, err := db.Exec(ctx, `SELECT pg_advisory_lock(184467)`); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer db.Exec(context.Background(), `SELECT pg_advisory_unlock(184467)`)
	for _, item := range items {
		var existing string
		err := db.QueryRow(ctx, `SELECT sha256 FROM platform_schema_migrations WHERE name=$1`, item.name).Scan(&existing)
		if err == nil {
			if existing != item.checksum {
				return fmt.Errorf("applied migration checksum changed: %s", item.name)
			}
			fmt.Printf("SKIP %s\n", item.name)
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inspect migration %s: %w", item.name, err)
		}
		tx, beginErr := db.Begin(ctx)
		if beginErr != nil {
			return fmt.Errorf("begin %s: %w", item.name, beginErr)
		}
		if _, err = tx.Exec(ctx, item.sql); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO platform_schema_migrations(name,sha256) VALUES($1,$2)`, item.name, item.checksum)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", item.name, err)
		}
		if err = tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", item.name, err)
		}
		fmt.Printf("APPLIED %s\n", item.name)
	}
	return nil
}
