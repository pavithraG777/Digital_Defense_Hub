package preencryption

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	defaultCorrelationBatchSize = 100
	maximumCorrelationBatchSize = 1000
)

// RefreshPendingDetectionCorrelations links pre-encryption detections
// with Threat Engine and Incident Engine records through contributing
// file-event IDs.
func (r *Repository) RefreshPendingDetectionCorrelations(
	ctx context.Context,
	batchSize int,
	updatedAt time.Time,
) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New(
			"pre-encryption repository is unavailable",
		)
	}

	if batchSize <= 0 {
		batchSize =
			defaultCorrelationBatchSize
	}

	if batchSize >
		maximumCorrelationBatchSize {
		batchSize =
			maximumCorrelationBatchSize
	}

	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	} else {
		updatedAt = updatedAt.UTC()
	}

	const query = `
		WITH candidates AS (
			SELECT
				detection.id,
				detection.organization_id,
				detection.threat_id
					AS existing_threat_id,
				detection.incident_id
					AS existing_incident_id,
				(
					SELECT threat.id
					FROM
						pre_encryption_detection_events
							AS detection_event
					INNER JOIN threats AS threat
						ON threat.organization_id =
							detection.organization_id
						AND threat.deleted_at IS NULL
						AND (
							threat.primary_event_id =
								detection_event.file_event_id
							OR EXISTS (
								SELECT 1
								FROM threat_file_events
									AS threat_event
								WHERE
									threat_event.threat_id =
										threat.id
									AND threat_event.file_event_id =
										detection_event.file_event_id
							)
						)
					WHERE
						detection_event.detection_id =
							detection.id
						AND detection_event.organization_id =
							detection.organization_id
					ORDER BY
						threat.threat_score DESC,
						threat.created_at ASC,
						threat.id ASC
					LIMIT 1
				) AS matched_threat_id
			FROM pre_encryption_detections
				AS detection
			WHERE
				detection.threat_id IS NULL
				OR detection.incident_id IS NULL
			ORDER BY
				detection.detected_at DESC,
				detection.detection_sequence DESC
			LIMIT $1
		),
		resolved AS (
			SELECT
				candidate.id,
				candidate.organization_id,
				COALESCE(
					candidate.existing_threat_id,
					candidate.matched_threat_id
				) AS threat_id,
				COALESCE(
					candidate.existing_incident_id,
					(
						SELECT incident_threat.incident_id
						FROM incident_threats
							AS incident_threat
						WHERE
							incident_threat.threat_id =
								COALESCE(
									candidate.existing_threat_id,
									candidate.matched_threat_id
								)
						ORDER BY
							incident_threat.added_at DESC,
							incident_threat.incident_id ASC
						LIMIT 1
					)
				) AS incident_id
			FROM candidates AS candidate
		)
		UPDATE pre_encryption_detections
			AS detection
		SET
			threat_id = COALESCE(
				detection.threat_id,
				resolved.threat_id
			),
			incident_id = COALESCE(
				detection.incident_id,
				resolved.incident_id
			),
			updated_at = $2
		FROM resolved
		WHERE
			detection.id = resolved.id
			AND detection.organization_id =
				resolved.organization_id
			AND (
				(
					detection.threat_id IS NULL
					AND resolved.threat_id IS NOT NULL
				)
				OR (
					detection.incident_id IS NULL
					AND resolved.incident_id IS NOT NULL
				)
			);
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		batchSize,
		updatedAt,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"refresh pre-encryption detection correlations: %w",
			err,
		)
	}

	return commandTag.RowsAffected(), nil
}
