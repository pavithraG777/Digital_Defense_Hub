package adaptivedeception

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrAdaptiveDeceptionRepositoryUnavailable = errors.New(
		"adaptive deception repository is unavailable",
	)

	ErrCanaryFileNotFound = errors.New(
		"canary file not found",
	)

	ErrCanaryHealthCheckNotFound = errors.New(
		"canary health check not found",
	)

	ErrCanaryRotationNotFound = errors.New(
		"canary rotation not found",
	)

	ErrCanaryFingerprintNotFound = errors.New(
		"canary interaction fingerprint not found",
	)
)

// Repository provides database access for adaptive
// deception health, rotation and fingerprint workflows.
type Repository struct {
	db *pgxpool.Pool
}

// CanaryFileSnapshot contains the current persisted state
// required to verify and rotate one canary file.
type CanaryFileSnapshot struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`
	PolicyID       *uuid.UUID `json:"policy_id,omitempty"`

	CanaryCode string `json:"canary_code"`
	FileName   string `json:"file_name"`
	FilePath   string `json:"file_path"`

	FileExtension *string `json:"file_extension,omitempty"`
	MimeType      *string `json:"mime_type,omitempty"`
	CanaryType    string  `json:"canary_type"`

	OriginalFileHash string `json:"original_file_hash"`
	HashAlgorithm    string `json:"hash_algorithm"`
	FileSizeBytes    *int64 `json:"file_size_bytes,omitempty"`

	TrackingIdentifier string `json:"tracking_identifier"`

	ContainsHoneytoken   bool       `json:"contains_honeytoken"`
	HoneytokenID         *uuid.UUID `json:"honeytoken_id,omitempty"`
	LinkedHoneytokenCode *string    `json:"linked_honeytoken_code,omitempty"`

	DeployedDeviceName       *string `json:"deployed_device_name,omitempty"`
	DeployedDeviceIdentifier *string `json:"deployed_device_identifier,omitempty"`

	AccessCount     int        `json:"access_count"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	DeployedAt      *time.Time `json:"deployed_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`

	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewRepository(
	databasePool *pgxpool.Pool,
) *Repository {
	return &Repository{
		db: databasePool,
	}
}

func (r *Repository) GetCanaryFileSnapshot(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryFileID uuid.UUID,
) (*CanaryFileSnapshot, error) {
	if r == nil || r.db == nil {
		return nil,
			ErrAdaptiveDeceptionRepositoryUnavailable
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if canaryFileID == uuid.Nil {
		return nil, errors.New(
			"canary file ID is required",
		)
	}

	const query = `
		SELECT
			id,
			organization_id,
			department_id,
			policy_id,
			canary_code,
			file_name,
			file_path,
			file_extension,
			mime_type,
			canary_type,
			original_file_hash,
			hash_algorithm,
			file_size_bytes,
			tracking_identifier,
						contains_honeytoken,
			honeytoken_id,
			(
				SELECT linked_honeytoken.honeytoken_code
				FROM honeytokens linked_honeytoken
				WHERE
					linked_honeytoken.id =
						canary_files.honeytoken_id
					AND linked_honeytoken.organization_id =
						canary_files.organization_id
				LIMIT 1
			) AS linked_honeytoken_code,
			deployed_device_name,
			deployed_device_identifier,
			access_count,
			last_triggered_at,
			deployed_at,
			expires_at,
			status,
			created_at,
			updated_at
		FROM canary_files
		WHERE
			organization_id = $1
			AND id = $2
			AND deleted_at IS NULL;
	`

	var snapshot CanaryFileSnapshot

	err := r.db.QueryRow(
		ctx,
		query,
		organizationID,
		canaryFileID,
	).Scan(
		&snapshot.ID,
		&snapshot.OrganizationID,
		&snapshot.DepartmentID,
		&snapshot.PolicyID,
		&snapshot.CanaryCode,
		&snapshot.FileName,
		&snapshot.FilePath,
		&snapshot.FileExtension,
		&snapshot.MimeType,
		&snapshot.CanaryType,
		&snapshot.OriginalFileHash,
		&snapshot.HashAlgorithm,
		&snapshot.FileSizeBytes,
		&snapshot.TrackingIdentifier,
		&snapshot.ContainsHoneytoken,
		&snapshot.HoneytokenID,
		&snapshot.LinkedHoneytokenCode,
		&snapshot.DeployedDeviceName,
		&snapshot.DeployedDeviceIdentifier,
		&snapshot.AccessCount,
		&snapshot.LastTriggeredAt,
		&snapshot.DeployedAt,
		&snapshot.ExpiresAt,
		&snapshot.Status,
		&snapshot.CreatedAt,
		&snapshot.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCanaryFileNotFound
		}

		return nil, fmt.Errorf(
			"get canary file snapshot: %w",
			err,
		)
	}

	snapshot.CanaryCode =
		NormalizeConstant(
			snapshot.CanaryCode,
		)

	snapshot.CanaryType =
		NormalizeConstant(
			snapshot.CanaryType,
		)

	snapshot.HashAlgorithm =
		NormalizeConstant(
			snapshot.HashAlgorithm,
		)

	snapshot.Status =
		NormalizeConstant(
			snapshot.Status,
		)

	snapshot.CreatedAt =
		snapshot.CreatedAt.UTC()

	snapshot.UpdatedAt =
		snapshot.UpdatedAt.UTC()

	snapshot.LastTriggeredAt =
		utcTimePointer(
			snapshot.LastTriggeredAt,
		)

	snapshot.DeployedAt =
		utcTimePointer(
			snapshot.DeployedAt,
		)

	snapshot.ExpiresAt =
		utcTimePointer(
			snapshot.ExpiresAt,
		)

	return &snapshot, nil
}

func utcTimePointer(
	value *time.Time,
) *time.Time {
	if value == nil {
		return nil
	}

	utcValue := value.UTC()

	return &utcValue
}
