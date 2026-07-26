package adaptivedeception

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrInvalidCanaryRotationState = errors.New(
	"invalid canary rotation state",
)

// RotationCompletion contains the new active canary
// identity produced by a successful rotation.
type RotationCompletion struct {
	NewFileName           string
	NewFilePath           string
	NewFileHash           string
	NewTrackingIdentifier string
	NewFileSizeBytes      int64
	NewExpiresAt          *time.Time

	Metadata map[string]any
}

func (r *Repository) MarkRotationProcessing(
	ctx context.Context,
	organizationID uuid.UUID,
	rotationID uuid.UUID,
) (*CanaryRotation, error) {
	if r == nil || r.db == nil {
		return nil,
			ErrAdaptiveDeceptionRepositoryUnavailable
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if rotationID == uuid.Nil {
		return nil, errors.New(
			"rotation ID is required",
		)
	}

	const query = `
		UPDATE canary_rotations
		SET
			status = 'PROCESSING',
			started_at = CURRENT_TIMESTAMP,
			error_message = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			organization_id = $1
			AND id = $2
			AND status = 'PENDING'
		RETURNING ` + canaryRotationSelectColumns + `;
	`

	rotation, err := scanCanaryRotation(
		r.db.QueryRow(
			ctx,
			query,
			organizationID,
			rotationID,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil,
				ErrInvalidCanaryRotationState
		}

		return nil, fmt.Errorf(
			"mark canary rotation processing: %w",
			err,
		)
	}

	return rotation, nil
}

func (r *Repository) CompleteRotation(
	ctx context.Context,
	organizationID uuid.UUID,
	rotationID uuid.UUID,
	canaryFileID uuid.UUID,
	completion RotationCompletion,
) (*CanaryRotation, error) {
	if r == nil || r.db == nil {
		return nil,
			ErrAdaptiveDeceptionRepositoryUnavailable
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if rotationID == uuid.Nil {
		return nil, errors.New(
			"rotation ID is required",
		)
	}

	if canaryFileID == uuid.Nil {
		return nil, errors.New(
			"canary file ID is required",
		)
	}

	completion.NewFileName =
		strings.TrimSpace(
			completion.NewFileName,
		)

	completion.NewFilePath =
		strings.TrimSpace(
			completion.NewFilePath,
		)

	completion.NewFileHash =
		strings.ToLower(
			strings.TrimSpace(
				completion.NewFileHash,
			),
		)

	completion.NewTrackingIdentifier =
		strings.TrimSpace(
			completion.NewTrackingIdentifier,
		)

	if completion.NewFileName == "" ||
		completion.NewFilePath == "" ||
		completion.NewFileHash == "" ||
		completion.NewTrackingIdentifier == "" {
		return nil, errors.New(
			"new canary rotation values are required",
		)
	}

	if completion.NewFileSizeBytes < 0 {
		return nil, errors.New(
			"new canary file size cannot be negative",
		)
	}

	completion.NewExpiresAt =
		utcTimePointer(
			completion.NewExpiresAt,
		)

	if completion.Metadata == nil {
		completion.Metadata =
			make(map[string]any)
	}

	completion.Metadata["new_file_size_bytes"] =
		completion.NewFileSizeBytes

	metadataJSON, err := json.Marshal(
		completion.Metadata,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode rotation completion metadata: %w",
			err,
		)
	}

	transaction, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin canary rotation completion transaction: %w",
			err,
		)
	}
	defer func() {
		_ = transaction.Rollback(ctx)
	}()

	const updateCanaryQuery = `
		UPDATE canary_files
		SET
			file_name = $3,
			file_path = $4,
			file_extension = $5,
			original_file_hash = $6,
			file_size_bytes = $7,
			tracking_identifier = $8,
			expires_at = $9,
			status = 'ACTIVE',
			access_count = 0,
			last_triggered_at = NULL,
			deployed_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			organization_id = $1
			AND id = $2
			AND deleted_at IS NULL;
	`

	fileExtension :=
		fileExtensionFromName(
			completion.NewFileName,
		)

	commandTag, err := transaction.Exec(
		ctx,
		updateCanaryQuery,
		organizationID,
		canaryFileID,
		completion.NewFileName,
		completion.NewFilePath,
		fileExtension,
		completion.NewFileHash,
		completion.NewFileSizeBytes,
		completion.NewTrackingIdentifier,
		completion.NewExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"update rotated canary file: %w",
			err,
		)
	}

	if commandTag.RowsAffected() != 1 {
		return nil, ErrCanaryFileNotFound
	}

	const completeRotationQuery = `
		UPDATE canary_rotations
		SET
			new_file_name = $3,
			new_file_path = $4,
			new_file_hash = $5,
			new_tracking_identifier = $6,
			status = 'COMPLETED',
			error_message = NULL,
			rotation_metadata =
				rotation_metadata || $7::jsonb,
			completed_at = CURRENT_TIMESTAMP,
			failed_at = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			organization_id = $1
			AND id = $2
			AND canary_file_id = $8
			AND status = 'PROCESSING'
		RETURNING ` + canaryRotationSelectColumns + `;
	`

	rotation, err := scanCanaryRotation(
		transaction.QueryRow(
			ctx,
			completeRotationQuery,
			organizationID,
			rotationID,
			completion.NewFileName,
			completion.NewFilePath,
			completion.NewFileHash,
			completion.NewTrackingIdentifier,
			metadataJSON,
			canaryFileID,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil,
				ErrInvalidCanaryRotationState
		}

		return nil, fmt.Errorf(
			"complete canary rotation: %w",
			err,
		)
	}

	if err = transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit canary rotation completion: %w",
			err,
		)
	}

	return rotation, nil
}

func (r *Repository) FailRotation(
	ctx context.Context,
	organizationID uuid.UUID,
	rotationID uuid.UUID,
	errorMessage string,
	metadata map[string]any,
) (*CanaryRotation, error) {
	if r == nil || r.db == nil {
		return nil,
			ErrAdaptiveDeceptionRepositoryUnavailable
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if rotationID == uuid.Nil {
		return nil, errors.New(
			"rotation ID is required",
		)
	}

	errorMessage =
		strings.TrimSpace(errorMessage)

	if errorMessage == "" {
		errorMessage =
			"Canary rotation failed"
	}

	if metadata == nil {
		metadata =
			make(map[string]any)
	}

	metadataJSON, err := json.Marshal(
		metadata,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode rotation failure metadata: %w",
			err,
		)
	}

	const query = `
		UPDATE canary_rotations
		SET
			status = 'FAILED',
			error_message = $3,
			rotation_metadata =
				rotation_metadata || $4::jsonb,
			failed_at = CURRENT_TIMESTAMP,
			completed_at = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			organization_id = $1
			AND id = $2
			AND status IN (
				'PENDING',
				'PROCESSING'
			)
		RETURNING ` + canaryRotationSelectColumns + `;
	`

	rotation, err := scanCanaryRotation(
		r.db.QueryRow(
			ctx,
			query,
			organizationID,
			rotationID,
			errorMessage,
			metadataJSON,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil,
				ErrInvalidCanaryRotationState
		}

		return nil, fmt.Errorf(
			"fail canary rotation: %w",
			err,
		)
	}

	return rotation, nil
}

func fileExtensionFromName(
	fileName string,
) *string {
	fileName =
		strings.TrimSpace(fileName)

	lastDotIndex :=
		strings.LastIndex(
			fileName,
			".",
		)

	if lastDotIndex < 0 ||
		lastDotIndex ==
			len(fileName)-1 {
		return nil
	}

	extension :=
		strings.ToLower(
			fileName[lastDotIndex:],
		)

	return &extension
}
