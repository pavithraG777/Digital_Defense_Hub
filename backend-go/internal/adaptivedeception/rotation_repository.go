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
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrActiveCanaryRotationExists = errors.New(
	"an active canary rotation already exists",
)

const canaryRotationSelectColumns = `
	id,
	rotation_sequence,
	organization_id,
	canary_file_id,
	policy_id,
	rotation_reason,
	rotation_strategy,
	old_file_name,
	new_file_name,
	old_file_path,
	new_file_path,
	old_file_hash,
	new_file_hash,
	old_tracking_identifier,
	new_tracking_identifier,
	status,
	requested_by,
	error_message,
	rotation_metadata,
	requested_at,
	started_at,
	completed_at,
	failed_at,
	created_at,
	updated_at
`

type rotationRowScanner interface {
	Scan(destinations ...any) error
}

func (r *Repository) CreateRotation(
	ctx context.Context,
	rotation *CanaryRotation,
) (*CanaryRotation, error) {
	if r == nil || r.db == nil {
		return nil,
			ErrAdaptiveDeceptionRepositoryUnavailable
	}

	if rotation == nil {
		return nil, errors.New(
			"canary rotation is required",
		)
	}

	if rotation.ID == uuid.Nil {
		rotation.ID = uuid.New()
	}

	if rotation.OrganizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if rotation.CanaryFileID == uuid.Nil {
		return nil, errors.New(
			"canary file ID is required",
		)
	}

	rotation.RotationReason =
		NormalizeConstant(
			rotation.RotationReason,
		)

	if !IsSupportedRotationReason(
		rotation.RotationReason,
	) {
		return nil, errors.New(
			"unsupported canary rotation reason",
		)
	}

	rotation.RotationStrategy =
		NormalizeConstant(
			rotation.RotationStrategy,
		)

	if !IsSupportedRotationStrategy(
		rotation.RotationStrategy,
	) {
		return nil, errors.New(
			"unsupported canary rotation strategy",
		)
	}

	rotation.Status =
		NormalizeConstant(
			rotation.Status,
		)

	if rotation.Status == "" {
		rotation.Status =
			RotationStatusPending
	}

	if rotation.Status !=
		RotationStatusPending {
		return nil, errors.New(
			"new canary rotation must use PENDING status",
		)
	}

	rotation.OldFileName =
		normalizeOptionalString(
			rotation.OldFileName,
		)

	rotation.NewFileName =
		normalizeOptionalString(
			rotation.NewFileName,
		)

	rotation.OldFilePath =
		normalizeOptionalString(
			rotation.OldFilePath,
		)

	rotation.NewFilePath =
		normalizeOptionalString(
			rotation.NewFilePath,
		)

	rotation.OldFileHash =
		normalizeOptionalLowercaseString(
			rotation.OldFileHash,
		)

	rotation.NewFileHash =
		normalizeOptionalLowercaseString(
			rotation.NewFileHash,
		)

	rotation.OldTrackingIdentifier =
		normalizeOptionalString(
			rotation.OldTrackingIdentifier,
		)

	rotation.NewTrackingIdentifier =
		normalizeOptionalString(
			rotation.NewTrackingIdentifier,
		)

	rotation.ErrorMessage =
		normalizeOptionalString(
			rotation.ErrorMessage,
		)

	if rotation.Metadata == nil {
		rotation.Metadata =
			make(map[string]any)
	}

	if rotation.RequestedAt.IsZero() {
		rotation.RequestedAt =
			time.Now().UTC()
	} else {
		rotation.RequestedAt =
			rotation.RequestedAt.UTC()
	}

	metadataJSON, err := json.Marshal(
		rotation.Metadata,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode canary rotation metadata: %w",
			err,
		)
	}

	const query = `
		INSERT INTO canary_rotations (
			id,
			organization_id,
			canary_file_id,
			policy_id,
			rotation_reason,
			rotation_strategy,
			old_file_name,
			new_file_name,
			old_file_path,
			new_file_path,
			old_file_hash,
			new_file_hash,
			old_tracking_identifier,
			new_tracking_identifier,
			status,
			requested_by,
			error_message,
			rotation_metadata,
			requested_at
		)
		VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15,
			$16, $17, $18, $19
		)
		RETURNING ` + canaryRotationSelectColumns + `;
	`

	result, err := scanCanaryRotation(
		r.db.QueryRow(
			ctx,
			query,
			rotation.ID,
			rotation.OrganizationID,
			rotation.CanaryFileID,
			rotation.PolicyID,
			rotation.RotationReason,
			rotation.RotationStrategy,
			rotation.OldFileName,
			rotation.NewFileName,
			rotation.OldFilePath,
			rotation.NewFilePath,
			rotation.OldFileHash,
			rotation.NewFileHash,
			rotation.OldTrackingIdentifier,
			rotation.NewTrackingIdentifier,
			rotation.Status,
			rotation.RequestedBy,
			rotation.ErrorMessage,
			metadataJSON,
			rotation.RequestedAt,
		),
	)
	if err != nil {
		var databaseError *pgconn.PgError

		if errors.As(
			err,
			&databaseError,
		) &&
			databaseError.Code == "23505" {
			return nil,
				ErrActiveCanaryRotationExists
		}

		return nil, fmt.Errorf(
			"create canary rotation: %w",
			err,
		)
	}

	return result, nil
}

func (r *Repository) GetRotation(
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
		SELECT ` + canaryRotationSelectColumns + `
		FROM canary_rotations
		WHERE
			organization_id = $1
			AND id = $2;
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
				ErrCanaryRotationNotFound
		}

		return nil, fmt.Errorf(
			"get canary rotation: %w",
			err,
		)
	}

	return rotation, nil
}

func (r *Repository) GetActiveRotation(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryFileID uuid.UUID,
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

	if canaryFileID == uuid.Nil {
		return nil, errors.New(
			"canary file ID is required",
		)
	}

	const query = `
		SELECT ` + canaryRotationSelectColumns + `
		FROM canary_rotations
		WHERE
			organization_id = $1
			AND canary_file_id = $2
			AND status IN (
				'PENDING',
				'PROCESSING'
			)
		ORDER BY
			requested_at DESC,
			rotation_sequence DESC
		LIMIT 1;
	`

	rotation, err := scanCanaryRotation(
		r.db.QueryRow(
			ctx,
			query,
			organizationID,
			canaryFileID,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil,
				ErrCanaryRotationNotFound
		}

		return nil, fmt.Errorf(
			"get active canary rotation: %w",
			err,
		)
	}

	return rotation, nil
}

func scanCanaryRotation(
	scanner rotationRowScanner,
) (*CanaryRotation, error) {
	var rotation CanaryRotation
	var metadataJSON []byte

	err := scanner.Scan(
		&rotation.ID,
		&rotation.RotationSequence,
		&rotation.OrganizationID,
		&rotation.CanaryFileID,
		&rotation.PolicyID,
		&rotation.RotationReason,
		&rotation.RotationStrategy,
		&rotation.OldFileName,
		&rotation.NewFileName,
		&rotation.OldFilePath,
		&rotation.NewFilePath,
		&rotation.OldFileHash,
		&rotation.NewFileHash,
		&rotation.OldTrackingIdentifier,
		&rotation.NewTrackingIdentifier,
		&rotation.Status,
		&rotation.RequestedBy,
		&rotation.ErrorMessage,
		&metadataJSON,
		&rotation.RequestedAt,
		&rotation.StartedAt,
		&rotation.CompletedAt,
		&rotation.FailedAt,
		&rotation.CreatedAt,
		&rotation.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	rotation.Metadata =
		make(map[string]any)

	if len(metadataJSON) > 0 {
		if err = json.Unmarshal(
			metadataJSON,
			&rotation.Metadata,
		); err != nil {
			return nil, fmt.Errorf(
				"decode canary rotation metadata: %w",
				err,
			)
		}
	}

	rotation.RotationReason =
		NormalizeConstant(
			rotation.RotationReason,
		)

	rotation.RotationStrategy =
		NormalizeConstant(
			rotation.RotationStrategy,
		)

	rotation.Status =
		NormalizeConstant(
			rotation.Status,
		)

	rotation.RequestedAt =
		rotation.RequestedAt.UTC()

	rotation.StartedAt =
		utcTimePointer(
			rotation.StartedAt,
		)

	rotation.CompletedAt =
		utcTimePointer(
			rotation.CompletedAt,
		)

	rotation.FailedAt =
		utcTimePointer(
			rotation.FailedAt,
		)

	rotation.CreatedAt =
		rotation.CreatedAt.UTC()

	rotation.UpdatedAt =
		rotation.UpdatedAt.UTC()

	return &rotation, nil
}

func normalizeOptionalString(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	normalizedValue :=
		strings.TrimSpace(*value)

	if normalizedValue == "" {
		return nil
	}

	return &normalizedValue
}

func normalizeOptionalLowercaseString(
	value *string,
) *string {
	value =
		normalizeOptionalString(value)

	if value == nil {
		return nil
	}

	normalizedValue :=
		strings.ToLower(*value)

	return &normalizedValue
}
