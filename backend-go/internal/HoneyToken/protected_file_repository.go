package honeytoken

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrProtectedFileNotFound = errors.New("protected file not found")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(
	db *pgxpool.Pool,
) *Repository {
	return &Repository{
		db: db,
	}
}

// CreateProtectedFile registers a protected file inside the vault.
func (r *Repository) CreateProtectedFile(
	ctx context.Context,
	file *ProtectedFile,
) error {

	const query = `
		INSERT INTO protected_files (
			id,
			organization_id,
			department_id,
			owner_user_id,
			original_file_name,
			original_extension,
			original_file_path,
			protected_file_name,
			protected_file_path,
			metadata_file_name,
			metadata_file_path,
			file_size_bytes,
			mime_type,
			sha256_hash,
			encryption_algorithm,
			encryption_key_id,
			category,
			sensitivity,
			classification,
			retention_policy,
			retention_until,
			monitoring_enabled,
			honeytoken_enabled,
			canary_enabled,
			status,
			protected_at,
			archived_at,
			created_at,
			updated_at
		)
		VALUES (
			$1,$2,$3,$4,$5,$6,$7,
			$8,$9,$10,$11,$12,$13,$14,
			$15,$16,$17,$18,$19,$20,$21,
			$22,$23,$24,$25,$26,$27,
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP
		);
	`

	_, err := r.db.Exec(
		ctx,
		query,
		file.ID,
		file.OrganizationID,
		file.DepartmentID,
		file.OwnerUserID,
		file.OriginalFileName,
		file.OriginalExtension,
		file.OriginalFilePath,
		file.ProtectedFileName,
		file.ProtectedFilePath,
		file.MetadataFileName,
		file.MetadataFilePath,
		file.FileSizeBytes,
		file.MimeType,
		file.SHA256Hash,
		file.EncryptionAlgorithm,
		file.EncryptionKeyID,
		file.Category,
		file.Sensitivity,
		file.Classification,
		file.RetentionPolicy,
		file.RetentionUntil,
		file.MonitoringEnabled,
		file.HoneytokenEnabled,
		file.CanaryEnabled,
		file.Status,
		file.ProtectedAt,
		file.ArchivedAt,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to create protected file: %w",
			err,
		)
	}

	return nil
}

// FindProtectedFileByID returns one protected file.
func (r *Repository) FindProtectedFileByID(
	ctx context.Context,
	id uuid.UUID,
) (*ProtectedFile, error) {

	const query = `
		SELECT
			id,
			organization_id,
			department_id,
			owner_user_id,
			original_file_name,
			original_extension,
			original_file_path,
			protected_file_name,
			protected_file_path,
			metadata_file_name,
			metadata_file_path,
			file_size_bytes,
			mime_type,
			sha256_hash,
			encryption_algorithm,
			encryption_key_id,
			category,
			sensitivity,
			classification,
			retention_policy,
			retention_until,
			monitoring_enabled,
			honeytoken_enabled,
			canary_enabled,
			status,
			protected_at,
			archived_at,
			created_at,
			updated_at,
			deleted_at
		FROM protected_files
		WHERE
			id=$1
			AND deleted_at IS NULL
		LIMIT 1;
	`

	var file ProtectedFile

	err := r.db.QueryRow(
		ctx,
		query,
		id,
	).Scan(
		&file.ID,
		&file.OrganizationID,
		&file.DepartmentID,
		&file.OwnerUserID,
		&file.OriginalFileName,
		&file.OriginalExtension,
		&file.OriginalFilePath,
		&file.ProtectedFileName,
		&file.ProtectedFilePath,
		&file.MetadataFileName,
		&file.MetadataFilePath,
		&file.FileSizeBytes,
		&file.MimeType,
		&file.SHA256Hash,
		&file.EncryptionAlgorithm,
		&file.EncryptionKeyID,
		&file.Category,
		&file.Sensitivity,
		&file.Classification,
		&file.RetentionPolicy,
		&file.RetentionUntil,
		&file.MonitoringEnabled,
		&file.HoneytokenEnabled,
		&file.CanaryEnabled,
		&file.Status,
		&file.ProtectedAt,
		&file.ArchivedAt,
		&file.CreatedAt,
		&file.UpdatedAt,
		&file.DeletedAt,
	)

	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProtectedFileNotFound
		}

		return nil, fmt.Errorf(
			"failed to find protected file: %w",
			err,
		)
	}

	return &file, nil
}
