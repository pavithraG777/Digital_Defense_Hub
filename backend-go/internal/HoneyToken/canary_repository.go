package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrCanaryFileNotFound             = errors.New("canary file not found")
	ErrCanaryFileCodeExists           = errors.New("canary file code already exists")
	ErrCanaryFilePathExists           = errors.New("canary file path already exists")
	ErrCanaryTrackingIdentifierExists = errors.New("canary tracking identifier already exists")
	ErrCanaryFileNotDeployable        = errors.New("canary file cannot be deployed")
	ErrCanaryDepartmentNotFound       = errors.New("canary department not found in organization")
	ErrCanaryPolicyNotFound           = errors.New("canary policy not found in organization")
	ErrCanaryHoneytokenNotFound       = errors.New("canary honeytoken not found in organization")
	ErrCanaryOwnerNotFound            = errors.New("canary owner not found in organization")
	ErrCanaryCreatorNotFound          = errors.New("canary creator not found in organization")
	ErrCanaryFileNotMonitorable       = errors.New("canary file is not monitorable")
)

const canaryFileSelectColumns = `
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
	description,
	original_file_hash,
	hash_algorithm,
	file_size_bytes,
	tracking_identifier,
	contains_honeytoken,
	honeytoken_id,
	deployed_device_name,
	deployed_device_identifier,
	owner_user_id,
	created_by,
	access_count,
	last_triggered_at,
	deployed_at,
	expires_at,
	status,
	created_at,
	updated_at,
	deleted_at
`

type CanaryFileListFilter struct {
	OrganizationID uuid.UUID
	DepartmentID   *uuid.UUID
	CanaryType     string
	Status         string
	Limit          int
	Offset         int
}

// CreateCanaryFile stores generated canary metadata.
func (r *Repository) CreateCanaryFile(
	ctx context.Context,
	canary *CanaryFile,
) error {
	if canary == nil {
		return errors.New("canary file is required")
	}

	if canary.ID == uuid.Nil {
		return errors.New("canary file ID is required")
	}

	if canary.OrganizationID == uuid.Nil {
		return errors.New("organization ID is required")
	}

	const query = `
		INSERT INTO canary_files (
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
			description,
			original_file_hash,
			hash_algorithm,
			file_size_bytes,
			tracking_identifier,
			contains_honeytoken,
			honeytoken_id,
			deployed_device_name,
			deployed_device_identifier,
			owner_user_id,
			created_by,
			access_count,
			last_triggered_at,
			deployed_at,
			expires_at,
			status,
			created_at,
			updated_at
		)
		VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
			$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
			$21,$22,$23,$24,$25,$26,
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP
		)
		RETURNING created_at, updated_at;
	`

	err := r.db.QueryRow(
		ctx,
		query,
		canary.ID,
		canary.OrganizationID,
		canary.DepartmentID,
		canary.PolicyID,
		canary.CanaryCode,
		canary.FileName,
		canary.FilePath,
		canary.FileExtension,
		canary.MimeType,
		canary.CanaryType,
		canary.Description,
		canary.OriginalFileHash,
		canary.HashAlgorithm,
		canary.FileSizeBytes,
		canary.TrackingIdentifier,
		canary.ContainsHoneytoken,
		canary.HoneytokenID,
		canary.DeployedDeviceName,
		canary.DeployedDeviceIdentifier,
		canary.OwnerUserID,
		canary.CreatedBy,
		canary.AccessCount,
		canary.LastTriggeredAt,
		canary.DeployedAt,
		canary.ExpiresAt,
		canary.Status,
	).Scan(
		&canary.CreatedAt,
		&canary.UpdatedAt,
	)

	if err != nil {
		return mapCanaryFileWriteError(err, "failed to create canary file")
	}

	return nil
}

// FindCanaryFileByID returns one tenant-isolated canary file.
func (r *Repository) FindCanaryFileByID(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryID uuid.UUID,
) (*CanaryFile, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}

	if canaryID == uuid.Nil {
		return nil, errors.New("canary file ID is required")
	}

	query := `
		SELECT ` + canaryFileSelectColumns + `
		FROM canary_files
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL
		LIMIT 1;
	`

	canary, err := scanCanaryFile(
		r.db.QueryRow(ctx, query, canaryID, organizationID),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCanaryFileNotFound
		}

		return nil, fmt.Errorf("failed to find canary file: %w", err)
	}

	return canary, nil
}

// ListCanaryFiles returns paginated tenant-isolated canary files.
func (r *Repository) ListCanaryFiles(
	ctx context.Context,
	filter CanaryFileListFilter,
) ([]CanaryFile, int64, error) {
	filter = normalizeCanaryFileListFilter(filter)

	if filter.OrganizationID == uuid.Nil {
		return nil, 0, errors.New("organization ID is required")
	}

	whereClause, queryArguments := buildCanaryFileFilter(filter)

	countQuery := `
		SELECT COUNT(*)
		FROM canary_files
		WHERE ` + whereClause + `;
	`

	var total int64

	if err := r.db.QueryRow(
		ctx,
		countQuery,
		queryArguments...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count canary files: %w", err)
	}

	dataArguments := append([]any(nil), queryArguments...)
	limitPosition := len(dataArguments) + 1
	offsetPosition := len(dataArguments) + 2

	dataArguments = append(
		dataArguments,
		filter.Limit,
		filter.Offset,
	)

	dataQuery := fmt.Sprintf(`
		SELECT %s
		FROM canary_files
		WHERE %s
		ORDER BY created_at DESC, id DESC
		LIMIT $%d
		OFFSET $%d;
	`,
		canaryFileSelectColumns,
		whereClause,
		limitPosition,
		offsetPosition,
	)

	rows, err := r.db.Query(ctx, dataQuery, dataArguments...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list canary files: %w", err)
	}
	defer rows.Close()

	canaryFiles := make([]CanaryFile, 0, filter.Limit)

	for rows.Next() {
		canary, scanErr := scanCanaryFile(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"failed to scan canary file: %w",
				scanErr,
			)
		}

		canaryFiles = append(canaryFiles, *canary)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"failed while reading canary files: %w",
			err,
		)
	}

	return canaryFiles, total, nil
}

// ValidateCanaryFileRelations prevents cross-organization references.
func (r *Repository) ValidateCanaryFileRelations(
	ctx context.Context,
	organizationID uuid.UUID,
	departmentID *uuid.UUID,
	policyID *uuid.UUID,
	honeytokenID *uuid.UUID,
	ownerUserID *uuid.UUID,
	createdBy *uuid.UUID,
) error {
	if organizationID == uuid.Nil {
		return errors.New("organization ID is required")
	}

	const query = `
		SELECT
			(
				$2::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM departments
					WHERE id = $2
					  AND organization_id = $1
				)
			),
			(
				$3::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM deception_policies
					WHERE id = $3
					  AND organization_id = $1
				)
			),
			(
				$4::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM honeytokens
					WHERE id = $4
					  AND organization_id = $1
					  AND deleted_at IS NULL
				)
			),
			(
				$5::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM users
					WHERE id = $5
					  AND organization_id = $1
				)
			),
			(
				$6::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM users
					WHERE id = $6
					  AND organization_id = $1
				)
			);
	`

	var (
		departmentValid bool
		policyValid     bool
		honeytokenValid bool
		ownerValid      bool
		creatorValid    bool
	)

	err := r.db.QueryRow(
		ctx,
		query,
		organizationID,
		departmentID,
		policyID,
		honeytokenID,
		ownerUserID,
		createdBy,
	).Scan(
		&departmentValid,
		&policyValid,
		&honeytokenValid,
		&ownerValid,
		&creatorValid,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to validate canary file relations: %w",
			err,
		)
	}

	switch {
	case !departmentValid:
		return ErrCanaryDepartmentNotFound
	case !policyValid:
		return ErrCanaryPolicyNotFound
	case !honeytokenValid:
		return ErrCanaryHoneytokenNotFound
	case !ownerValid:
		return ErrCanaryOwnerNotFound
	case !creatorValid:
		return ErrCanaryCreatorNotFound
	default:
		return nil
	}
}

// DeployCanaryFile activates a generated canary at its final location.
func (r *Repository) DeployCanaryFile(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryID uuid.UUID,
	filePath string,
	deviceName *string,
	deviceIdentifier *string,
) (*CanaryFile, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}

	if canaryID == uuid.Nil {
		return nil, errors.New("canary file ID is required")
	}

	if strings.TrimSpace(filePath) == "" {
		return nil, errors.New("canary file path is required")
	}

	query := `
		UPDATE canary_files
		SET
			file_path = $3,
			deployed_device_name = $4,
			deployed_device_identifier = $5,
			status = $6,
			deployed_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL
			AND status IN ($7, $8, $9)
			AND (
				expires_at IS NULL
				OR expires_at > CURRENT_TIMESTAMP
			)
		RETURNING ` + canaryFileSelectColumns + `;
	`

	canary, err := scanCanaryFile(
		r.db.QueryRow(
			ctx,
			query,
			canaryID,
			organizationID,
			filePath,
			deviceName,
			deviceIdentifier,
			CanaryStatusActive,
			CanaryStatusDraft,
			CanaryStatusDeployed,
			CanaryStatusInactive,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCanaryFileNotDeployable
		}

		return nil, mapCanaryFileWriteError(
			err,
			"failed to deploy canary file",
		)
	}

	return canary, nil
}

// DeactivateCanaryFile stops the monitor from claiming this deployed file.
// The physical copy and all evidence remain intact until an operator rotates
// or otherwise remediates it.
func (r *Repository) DeactivateCanaryFile(ctx context.Context, organizationID, canaryID uuid.UUID) (*CanaryFile, error) {
	query := `UPDATE canary_files SET status = $3, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL AND status IN ($4, $5, $6, $7)
		RETURNING ` + canaryFileSelectColumns + `;`
	canary, err := scanCanaryFile(r.db.QueryRow(ctx, query, canaryID, organizationID, CanaryStatusInactive,
		CanaryStatusActive, CanaryStatusTriggered, CanaryStatusTampered, CanaryStatusMissing))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCanaryFileNotDeployable
	}
	if err != nil {
		return nil, mapCanaryFileWriteError(err, "failed to deactivate canary file")
	}
	return canary, nil
}

// ListMonitorableCanaryFiles returns deployed Canary files watched by the
// internal monitoring service across all organizations.
func (r *Repository) ListMonitorableCanaryFiles(
	ctx context.Context,
) ([]CanaryFile, error) {
	query := `
		SELECT ` + canaryFileSelectColumns + `
		FROM canary_files
		WHERE
			status IN ($1, $2, $3, $4)
			AND deployed_at IS NOT NULL
			AND deleted_at IS NULL
			AND (
				expires_at IS NULL
				OR expires_at > CURRENT_TIMESTAMP
			)
		ORDER BY
			organization_id,
			id;
	`

	rows, err := r.db.Query(
		ctx,
		query,
		CanaryStatusActive,
		CanaryStatusTriggered,
		CanaryStatusTampered,
		CanaryStatusMissing,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to list monitorable canary files: %w",
			err,
		)
	}
	defer rows.Close()

	canaryFiles := make([]CanaryFile, 0)

	for rows.Next() {
		canary, scanErr := scanCanaryFile(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"failed to scan monitorable canary file: %w",
				scanErr,
			)
		}

		canaryFiles = append(canaryFiles, *canary)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"failed while reading monitorable canary files: %w",
			err,
		)
	}

	return canaryFiles, nil
}

// RecordCanaryFileTrigger atomically updates Canary state whenever the
// watcher detects modification, rename, removal or another suspicious event.
func (r *Repository) RecordCanaryFileTrigger(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryID uuid.UUID,
	status string,
) (*CanaryFile, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if canaryID == uuid.Nil {
		return nil, errors.New(
			"canary file ID is required",
		)
	}

	if !isCanaryTriggerStatus(status) {
		return nil, errors.New(
			"invalid canary trigger status",
		)
	}

	query := `
		UPDATE canary_files
		SET
			access_count = access_count + 1,
			last_triggered_at = CURRENT_TIMESTAMP,
			status = $3,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND status IN ($4, $5, $6, $7)
			AND deleted_at IS NULL
			AND (
				expires_at IS NULL
				OR expires_at > CURRENT_TIMESTAMP
			)
		RETURNING ` + canaryFileSelectColumns + `;
	`

	canary, err := scanCanaryFile(
		r.db.QueryRow(
			ctx,
			query,
			canaryID,
			organizationID,
			status,
			CanaryStatusActive,
			CanaryStatusTriggered,
			CanaryStatusTampered,
			CanaryStatusMissing,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCanaryFileNotMonitorable
		}

		return nil, fmt.Errorf(
			"failed to record canary file trigger: %w",
			err,
		)
	}

	return canary, nil
}

func isCanaryTriggerStatus(
	status string,
) bool {
	switch status {
	case CanaryStatusTriggered,
		CanaryStatusTampered,
		CanaryStatusMissing:
		return true

	default:
		return false
	}
}

func normalizeCanaryFileListFilter(
	filter CanaryFileListFilter,
) CanaryFileListFilter {
	if filter.Limit <= 0 {
		filter.Limit = 20
	}

	if filter.Limit > 100 {
		filter.Limit = 100
	}

	if filter.Offset < 0 {
		filter.Offset = 0
	}

	filter.CanaryType = strings.TrimSpace(filter.CanaryType)
	filter.Status = strings.TrimSpace(filter.Status)

	return filter
}

func buildCanaryFileFilter(
	filter CanaryFileListFilter,
) (string, []any) {
	conditions := []string{
		"organization_id = $1",
		"deleted_at IS NULL",
	}

	arguments := []any{
		filter.OrganizationID,
	}

	if filter.DepartmentID != nil {
		arguments = append(arguments, filter.DepartmentID)
		conditions = append(
			conditions,
			fmt.Sprintf("department_id = $%d", len(arguments)),
		)
	}

	if filter.CanaryType != "" {
		arguments = append(arguments, filter.CanaryType)
		conditions = append(
			conditions,
			fmt.Sprintf("canary_type = $%d", len(arguments)),
		)
	}

	if filter.Status != "" {
		arguments = append(arguments, filter.Status)
		conditions = append(
			conditions,
			fmt.Sprintf("status = $%d", len(arguments)),
		)
	}

	return strings.Join(conditions, " AND "), arguments
}

type canaryFileScanner interface {
	Scan(destinations ...any) error
}

func scanCanaryFile(
	scanner canaryFileScanner,
) (*CanaryFile, error) {
	var canary CanaryFile

	err := scanner.Scan(
		&canary.ID,
		&canary.OrganizationID,
		&canary.DepartmentID,
		&canary.PolicyID,
		&canary.CanaryCode,
		&canary.FileName,
		&canary.FilePath,
		&canary.FileExtension,
		&canary.MimeType,
		&canary.CanaryType,
		&canary.Description,
		&canary.OriginalFileHash,
		&canary.HashAlgorithm,
		&canary.FileSizeBytes,
		&canary.TrackingIdentifier,
		&canary.ContainsHoneytoken,
		&canary.HoneytokenID,
		&canary.DeployedDeviceName,
		&canary.DeployedDeviceIdentifier,
		&canary.OwnerUserID,
		&canary.CreatedBy,
		&canary.AccessCount,
		&canary.LastTriggeredAt,
		&canary.DeployedAt,
		&canary.ExpiresAt,
		&canary.Status,
		&canary.CreatedAt,
		&canary.UpdatedAt,
		&canary.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	return &canary, nil
}

func mapCanaryFileWriteError(
	err error,
	contextMessage string,
) error {
	var databaseError *pgconn.PgError

	if errors.As(err, &databaseError) &&
		databaseError.Code == "23505" {
		switch databaseError.ConstraintName {
		case "uq_canary_file_code":
			return ErrCanaryFileCodeExists

		case "uq_canary_file_path":
			return ErrCanaryFilePathExists

		case "canary_files_tracking_identifier_key":
			return ErrCanaryTrackingIdentifierExists
		}
	}

	return fmt.Errorf("%s: %w", contextMessage, err)
}
