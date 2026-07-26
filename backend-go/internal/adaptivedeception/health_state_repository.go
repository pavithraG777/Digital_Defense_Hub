package adaptivedeception

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const (
	CanaryFileStatusDraft     = "DRAFT"
	CanaryFileStatusDeployed  = "DEPLOYED"
	CanaryFileStatusActive    = "ACTIVE"
	CanaryFileStatusTriggered = "TRIGGERED"
	CanaryFileStatusTampered  = "TAMPERED"
	CanaryFileStatusMissing   = "MISSING"
	CanaryFileStatusInactive  = "INACTIVE"
	CanaryFileStatusExpired   = "EXPIRED"
	CanaryFileStatusArchived  = "ARCHIVED"
)

// SyncCanaryStatusWithHealth updates the source canary lifecycle
// status only when the health result requires a persisted state change.
func (r *Repository) SyncCanaryStatusWithHealth(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryFileID uuid.UUID,
	healthStatus string,
) (bool, error) {
	if r == nil || r.db == nil {
		return false,
			ErrAdaptiveDeceptionRepositoryUnavailable
	}

	if organizationID == uuid.Nil {
		return false, errors.New(
			"organization ID is required",
		)
	}

	if canaryFileID == uuid.Nil {
		return false, errors.New(
			"canary file ID is required",
		)
	}

	healthStatus =
		NormalizeConstant(
			healthStatus,
		)

	if !IsSupportedCanaryHealthStatus(
		healthStatus,
	) {
		return false, errors.New(
			"unsupported canary health status",
		)
	}

	canaryStatus, shouldUpdate :=
		canaryStatusFromHealth(
			healthStatus,
		)
	if !shouldUpdate {
		return false, nil
	}

	const query = `
		UPDATE canary_files
		SET
			status = $3,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			organization_id = $1
			AND id = $2
			AND deleted_at IS NULL
			AND status IN (
				'DEPLOYED',
				'ACTIVE',
				'TRIGGERED',
				'TAMPERED',
				'MISSING',
				'EXPIRED'
			)
			AND status <> $3;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		organizationID,
		canaryFileID,
		canaryStatus,
	)
	if err != nil {
		return false, fmt.Errorf(
			"synchronize canary health status: %w",
			err,
		)
	}

	return commandTag.RowsAffected() > 0, nil
}

func canaryStatusFromHealth(
	healthStatus string,
) (string, bool) {
	switch NormalizeConstant(
		healthStatus,
	) {
	case CanaryHealthStatusTampered:
		return CanaryFileStatusTampered, true

	case CanaryHealthStatusMissing:
		return CanaryFileStatusMissing, true

	case CanaryHealthStatusExpired:
		return CanaryFileStatusExpired, true

	default:
		return "", false
	}
}

func IsSupportedCanaryFileStatus(
	value string,
) bool {
	switch NormalizeConstant(value) {
	case CanaryFileStatusDraft,
		CanaryFileStatusDeployed,
		CanaryFileStatusActive,
		CanaryFileStatusTriggered,
		CanaryFileStatusTampered,
		CanaryFileStatusMissing,
		CanaryFileStatusInactive,
		CanaryFileStatusExpired,
		CanaryFileStatusArchived:
		return true

	default:
		return false
	}
}
