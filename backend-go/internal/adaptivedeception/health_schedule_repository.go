package adaptivedeception

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	defaultHealthTargetBatchSize = 50
	maximumHealthTargetBatchSize = 500
)

// CanaryHealthTarget identifies one canary file that
// requires a scheduled filesystem health verification.
type CanaryHealthTarget struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	CanaryFileID   uuid.UUID `json:"canary_file_id"`

	CanaryCode string `json:"canary_code"`
	FileName   string `json:"file_name"`
	FilePath   string `json:"file_path"`

	Status string `json:"status"`

	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	NextCheckAt   *time.Time `json:"next_check_at,omitempty"`
}

func (r *Repository) ListDueHealthCheckTargets(
	ctx context.Context,
	limit int,
) ([]CanaryHealthTarget, error) {
	if r == nil || r.db == nil {
		return nil,
			ErrAdaptiveDeceptionRepositoryUnavailable
	}

	if limit <= 0 {
		limit =
			defaultHealthTargetBatchSize
	}

	if limit >
		maximumHealthTargetBatchSize {
		limit =
			maximumHealthTargetBatchSize
	}

	const query = `
		SELECT
			canary.organization_id,
			canary.id,
			canary.canary_code,
			canary.file_name,
			canary.file_path,
			canary.status,
			latest_health.checked_at,
			latest_health.next_check_at
		FROM canary_files canary
		LEFT JOIN LATERAL (
			SELECT
				health.checked_at,
				health.next_check_at
			FROM canary_health_checks health
			WHERE
				health.organization_id =
					canary.organization_id
				AND health.canary_file_id =
					canary.id
			ORDER BY
				health.checked_at DESC,
				health.health_check_sequence DESC
			LIMIT 1
		) latest_health ON TRUE
		WHERE
			canary.deleted_at IS NULL
			AND canary.status IN (
				'DEPLOYED',
				'ACTIVE',
				'TRIGGERED',
				'TAMPERED',
				'MISSING'
			)
			AND (
				latest_health.next_check_at IS NULL
				OR latest_health.next_check_at <=
					CURRENT_TIMESTAMP
			)
		ORDER BY
			COALESCE(
				latest_health.next_check_at,
				canary.deployed_at,
				canary.created_at
			) ASC,
			canary.id ASC
		LIMIT $1;
	`

	rows, err := r.db.Query(
		ctx,
		query,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list due canary health targets: %w",
			err,
		)
	}
	defer rows.Close()

	targets := make(
		[]CanaryHealthTarget,
		0,
		limit,
	)

	for rows.Next() {
		var target CanaryHealthTarget

		if err = rows.Scan(
			&target.OrganizationID,
			&target.CanaryFileID,
			&target.CanaryCode,
			&target.FileName,
			&target.FilePath,
			&target.Status,
			&target.LastCheckedAt,
			&target.NextCheckAt,
		); err != nil {
			return nil, fmt.Errorf(
				"scan due canary health target: %w",
				err,
			)
		}

		if target.OrganizationID == uuid.Nil ||
			target.CanaryFileID == uuid.Nil {
			return nil, errors.New(
				"invalid due canary health target",
			)
		}

		target.Status =
			NormalizeConstant(
				target.Status,
			)

		target.LastCheckedAt =
			utcTimePointer(
				target.LastCheckedAt,
			)

		target.NextCheckAt =
			utcTimePointer(
				target.NextCheckAt,
			)

		targets = append(
			targets,
			target,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate due canary health targets: %w",
			err,
		)
	}

	return targets, nil
}
