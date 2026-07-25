package preencryption

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

var (
	ErrInvalidDetectionStatusTransition = errors.New(
		"invalid pre-encryption detection status transition",
	)

	ErrInvalidDetectionActionTransition = errors.New(
		"invalid pre-encryption detection action transition",
	)

	ErrNoDetectionWorkflowChanges = errors.New(
		"no pre-encryption detection workflow changes supplied",
	)
)

type DetectionWorkflowUpdate struct {
	OrganizationID uuid.UUID
	DetectionID    uuid.UUID
	UpdatedBy      uuid.UUID

	Status       *string
	ActionStatus *string

	ReviewNotes       *string
	MitigationSummary *string

	UpdatedAt time.Time
}

func (r *Repository) UpdateDetectionWorkflow(
	ctx context.Context,
	update DetectionWorkflowUpdate,
) (*Detection, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"pre-encryption repository is unavailable",
		)
	}

	if update.OrganizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if update.DetectionID == uuid.Nil {
		return nil, errors.New(
			"detection ID is required",
		)
	}

	if update.UpdatedBy == uuid.Nil {
		return nil, errors.New(
			"workflow user ID is required",
		)
	}

	if update.Status == nil &&
		update.ActionStatus == nil &&
		update.ReviewNotes == nil &&
		update.MitigationSummary == nil {
		return nil, ErrNoDetectionWorkflowChanges
	}

	if update.UpdatedAt.IsZero() {
		update.UpdatedAt = time.Now().UTC()
	} else {
		update.UpdatedAt =
			update.UpdatedAt.UTC()
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin pre-encryption workflow transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const stateQuery = `
		SELECT
			status,
			action_status
		FROM pre_encryption_detections
		WHERE
			id = $1
			AND organization_id = $2
		FOR UPDATE;
	`

	var currentStatus string
	var currentActionStatus string

	err = tx.QueryRow(
		ctx,
		stateQuery,
		update.DetectionID,
		update.OrganizationID,
	).Scan(
		&currentStatus,
		&currentActionStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDetectionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"load pre-encryption workflow state: %w",
			err,
		)
	}

	currentStatus =
		NormalizeConstant(
			currentStatus,
		)

	currentActionStatus =
		NormalizeConstant(
			currentActionStatus,
		)

	if update.Status != nil {
		normalizedStatus :=
			NormalizeConstant(
				*update.Status,
			)

		if !isAllowedDetectionStatusTransition(
			currentStatus,
			normalizedStatus,
		) {
			return nil, fmt.Errorf(
				"%w: %s to %s",
				ErrInvalidDetectionStatusTransition,
				currentStatus,
				normalizedStatus,
			)
		}

		update.Status = &normalizedStatus
	}

	if update.ActionStatus != nil {
		normalizedActionStatus :=
			NormalizeConstant(
				*update.ActionStatus,
			)

		if !isAllowedDetectionActionTransition(
			currentActionStatus,
			normalizedActionStatus,
		) {
			return nil, fmt.Errorf(
				"%w: %s to %s",
				ErrInvalidDetectionActionTransition,
				currentActionStatus,
				normalizedActionStatus,
			)
		}

		update.ActionStatus =
			&normalizedActionStatus
	}

	metadataUpdate := map[string]any{
		"workflow": map[string]any{
			"updated_by": update.UpdatedBy.String(),

			"updated_at": update.UpdatedAt.Format(
				time.RFC3339Nano,
			),
		},
	}

	if update.Status != nil {
		metadataUpdate["workflow"].(map[string]any)["status"] =
			*update.Status
	}

	if update.ActionStatus != nil {
		metadataUpdate["workflow"].(map[string]any)["action_status"] =
			*update.ActionStatus
	}

	if update.ReviewNotes != nil {
		metadataUpdate["review"] =
			map[string]any{
				"reviewed_by": update.UpdatedBy.String(),

				"reviewed_at": update.UpdatedAt.Format(
					time.RFC3339Nano,
				),

				"notes": strings.TrimSpace(
					*update.ReviewNotes,
				),
			}
	}

	if update.MitigationSummary != nil {
		metadataUpdate["mitigation"] =
			map[string]any{
				"updated_by": update.UpdatedBy.String(),

				"updated_at": update.UpdatedAt.Format(
					time.RFC3339Nano,
				),

				"summary": strings.TrimSpace(
					*update.MitigationSummary,
				),
			}
	}

	metadataJSON, err := json.Marshal(
		metadataUpdate,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode pre-encryption workflow metadata: %w",
			err,
		)
	}

	markReviewed :=
		update.ReviewNotes != nil ||
			(update.Status != nil &&
				*update.Status !=
					DetectionStatusOpen &&
				*update.Status !=
					DetectionStatusArchived)

	markMitigated :=
		update.Status != nil &&
			*update.Status ==
				DetectionStatusMitigated

	updateQuery := `
		UPDATE pre_encryption_detections
		SET
			status = COALESCE(
				$3::varchar,
				status
			),
			action_status = COALESCE(
				$4::varchar,
				action_status
			),
						metadata =
				jsonb_set(
					COALESCE(
						metadata,
						'{}'::jsonb
					),
					'{workflow}',
					COALESCE(
						metadata -> 'workflow',
						'{}'::jsonb
					) ||
					COALESCE(
						$5::jsonb -> 'workflow',
						'{}'::jsonb
					),
					true
				) ||
				(
					$5::jsonb -
					'workflow'
				),
			reviewed_at = CASE
				WHEN $6::boolean
					THEN COALESCE(
						reviewed_at,
						$8
					)
				ELSE reviewed_at
			END,
			mitigated_at = CASE
				WHEN $7::boolean
					THEN COALESCE(
						mitigated_at,
						$8
					)
				ELSE mitigated_at
			END,
			updated_at = $8
		WHERE
			id = $1
			AND organization_id = $2
		RETURNING ` + detectionSelectColumns + `;
	`

	detection, err := scanDetection(
		tx.QueryRow(
			ctx,
			updateQuery,
			update.DetectionID,
			update.OrganizationID,
			update.Status,
			update.ActionStatus,
			metadataJSON,
			markReviewed,
			markMitigated,
			update.UpdatedAt,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"update pre-encryption detection workflow: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit pre-encryption workflow transaction: %w",
			err,
		)
	}

	return detection, nil
}

func isAllowedDetectionStatusTransition(
	currentStatus string,
	nextStatus string,
) bool {
	currentStatus =
		NormalizeConstant(
			currentStatus,
		)

	nextStatus =
		NormalizeConstant(
			nextStatus,
		)

	if currentStatus == nextStatus {
		return true
	}

	switch currentStatus {
	case DetectionStatusOpen:
		switch nextStatus {
		case DetectionStatusInvestigating,
			DetectionStatusConfirmed,
			DetectionStatusFalsePositive,
			DetectionStatusArchived:
			return true
		}

	case DetectionStatusInvestigating:
		switch nextStatus {
		case DetectionStatusConfirmed,
			DetectionStatusFalsePositive,
			DetectionStatusMitigated,
			DetectionStatusArchived:
			return true
		}

	case DetectionStatusConfirmed:
		switch nextStatus {
		case DetectionStatusInvestigating,
			DetectionStatusMitigated,
			DetectionStatusArchived:
			return true
		}

	case DetectionStatusFalsePositive:
		switch nextStatus {
		case DetectionStatusInvestigating,
			DetectionStatusArchived:
			return true
		}

	case DetectionStatusMitigated:
		switch nextStatus {
		case DetectionStatusInvestigating,
			DetectionStatusArchived:
			return true
		}

	case DetectionStatusArchived:
		return nextStatus ==
			DetectionStatusInvestigating
	}

	return false
}

func isAllowedDetectionActionTransition(
	currentStatus string,
	nextStatus string,
) bool {
	currentStatus =
		NormalizeConstant(
			currentStatus,
		)

	nextStatus =
		NormalizeConstant(
			nextStatus,
		)

	if currentStatus == nextStatus {
		return true
	}

	switch currentStatus {
	case ActionStatusPending:
		switch nextStatus {
		case ActionStatusNotRequired,
			ActionStatusRequested:
			return true
		}

	case ActionStatusNotRequired:
		switch nextStatus {
		case ActionStatusPending,
			ActionStatusRequested:
			return true
		}

	case ActionStatusRequested:
		switch nextStatus {
		case ActionStatusCompleted,
			ActionStatusFailed:
			return true
		}

	case ActionStatusFailed:
		switch nextStatus {
		case ActionStatusRequested,
			ActionStatusNotRequired:
			return true
		}

	case ActionStatusCompleted:
		return false
	}

	return false
}
