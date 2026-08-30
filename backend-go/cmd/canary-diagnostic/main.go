package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/database"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	db, err := database.Connect(cfg, zap.NewNop())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close(zap.NewNop())

	nameFilter := "%PAVITHRA G HACKATHON NM 2026.PDF%"
	if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		nameFilter = "%" + strings.ToUpper(strings.TrimSpace(os.Args[1])) + "%"
	}

	rows, err := db.Pool.Query(context.Background(), `
		SELECT file_name, file_path, original_file_hash, status
		FROM canary_files
		WHERE deleted_at IS NULL
		  AND UPPER(file_name) LIKE $1
		ORDER BY created_at DESC
	`, nameFilter)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var name, path, baseline, status string
		if err = rows.Scan(&name, &path, &baseline, &status); err != nil {
			log.Fatal(err)
		}

		current, hashErr := fileSHA256(path)
		match := hashErr == nil && strings.EqualFold(current, baseline)
		fmt.Printf("name=%q status=%s\npath=%q\nexists=%t baseline_matches_disk=%t\n", name, status, path, hashErr == nil, match)
		if hashErr != nil {
			fmt.Printf("disk_error=%v\n", hashErr)
		}
		fmt.Println()
	}

	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
