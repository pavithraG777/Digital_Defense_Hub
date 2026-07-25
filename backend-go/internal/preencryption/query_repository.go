package preencryption

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultDetectionPageSize = 20
	maximumDetectionPageSize = 100
)

// DetectionListFilter contains normalized repository filters.
type DetectionListFilter struct {
	RiskLevel       string
	Classification  string
	DetectionStage  string
	DetectionMethod string

	Status       string
	ActionStatus string

	DeviceIdentifier string
	ProcessName      string

	RequiresHumanReview *bool

	DetectedFrom *time.Time
	DetectedTo   *time.Time

	Limit  int
	Offset int
}

const detectionFilterClause = `
	AND ($2::text = '' OR risk_level = $2)
	AND ($3::text = '' OR classification = $3)
	AND ($4::text = '' OR detection_stage = $4)
	AND ($5::text = '' OR detection_method = $5)
	AND ($6::text = '' OR status = $6)
	AND ($7::text = '' OR action_status = $7)
	AND (
		$8::text = ''
		OR device_identifier = $8
	)
	AND (
		$9::text = ''
		OR LOWER(process_name) =
			LOWER($9)
	)
	AND (
		$10::boolean IS NULL
		OR requires_human_review = $10
	)
	AND (
		$11::timestamp IS NULL
		OR detected_at >= $11
	)
	AND (
		$12::timestamp IS NULL
		OR detected_at <= $12
	)
`

func (r *Repository) ListDetections(
	ctx context.Context,
	organizationID uuid.UUID,
	filter DetectionListFilter,
) ([]Detection, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New(
			"pre-encryption repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, 0, errors.New(
			"organization ID is required",
		)
	}

	filter = normalizeDetectionListFilter(
		filter,
	)

	countQuery := `
		SELECT COUNT(*)
		FROM pre_encryption_detections
		WHERE organization_id = $1
	` + detectionFilterClause + `;
	`

	arguments := []any{
		organizationID,
		filter.RiskLevel,
		filter.Classification,
		filter.DetectionStage,
		filter.DetectionMethod,
		filter.Status,
		filter.ActionStatus,
		filter.DeviceIdentifier,
		filter.ProcessName,
		filter.RequiresHumanReview,
		filter.DetectedFrom,
		filter.DetectedTo,
	}

	var total int64

	if err := r.db.QueryRow(
		ctx,
		countQuery,
		arguments...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf(
			"count pre-encryption detections: %w",
			err,
		)
	}

	listQuery := `
		SELECT ` + detectionSelectColumns + `
		FROM pre_encryption_detections
		WHERE organization_id = $1
	` + detectionFilterClause + `
		ORDER BY
			detected_at DESC,
			detection_sequence DESC
		LIMIT $13
		OFFSET $14;
	`

	listArguments := append(
		arguments,
		filter.Limit,
		filter.Offset,
	)

	rows, err := r.db.Query(
		ctx,
		listQuery,
		listArguments...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list pre-encryption detections: %w",
			err,
		)
	}
	defer rows.Close()

	detections := make(
		[]Detection,
		0,
		filter.Limit,
	)

	for rows.Next() {
		detection, scanErr :=
			scanDetection(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan pre-encryption detection: %w",
				scanErr,
			)
		}

		detections = append(
			detections,
			*detection,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate pre-encryption detections: %w",
			err,
		)
	}

	return detections, total, nil
}

func (r *Repository) ListDetectionEvents(
	ctx context.Context,
	organizationID uuid.UUID,
	detectionID uuid.UUID,
) ([]DetectionEventResponse, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"pre-encryption repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if detectionID == uuid.Nil {
		return nil, errors.New(
			"detection ID is required",
		)
	}

	const query = `
		SELECT
			link.id,
			event.id,
			event.event_code,
			event.event_type,
			event.event_source,
			event.source_type,
			event.detection_method,
			event.file_name,
			event.file_path,
			event.previous_file_path,
			event.file_extension,
			event.file_size_before,
			event.file_size_after,
			event.previous_hash,
			event.current_hash,
			event.process_id,
			event.process_name,
			event.executable_path,
			event.parent_process_id,
			event.parent_process_name,
			event.command_line,
			event.device_name,
			event.device_identifier,
			event.severity,
			event.threat_score,
			event.is_suspicious,
			link.signal_types,
			link.contribution_score,
			event.occurred_at,
			link.linked_at
		FROM pre_encryption_detection_events link
		INNER JOIN file_events event
			ON event.id = link.file_event_id
			AND event.organization_id =
				link.organization_id
		WHERE
			link.organization_id = $1
			AND link.detection_id = $2
		ORDER BY
			event.occurred_at ASC,
			event.event_sequence ASC;
	`

	rows, err := r.db.Query(
		ctx,
		query,
		organizationID,
		detectionID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list pre-encryption detection events: %w",
			err,
		)
	}
	defer rows.Close()

	events := make(
		[]DetectionEventResponse,
		0,
	)

	for rows.Next() {
		var event DetectionEventResponse
		var signalTypesJSON []byte

		if err = rows.Scan(
			&event.LinkID,
			&event.FileEventID,
			&event.EventCode,
			&event.EventType,
			&event.EventSource,
			&event.SourceType,
			&event.DetectionMethod,
			&event.FileName,
			&event.FilePath,
			&event.PreviousFilePath,
			&event.FileExtension,
			&event.FileSizeBefore,
			&event.FileSizeAfter,
			&event.PreviousHash,
			&event.CurrentHash,
			&event.ProcessID,
			&event.ProcessName,
			&event.ExecutablePath,
			&event.ParentProcessID,
			&event.ParentProcessName,
			&event.CommandLine,
			&event.DeviceName,
			&event.DeviceIdentifier,
			&event.Severity,
			&event.ThreatScore,
			&event.IsSuspicious,
			&signalTypesJSON,
			&event.ContributionScore,
			&event.OccurredAt,
			&event.LinkedAt,
		); err != nil {
			return nil, fmt.Errorf(
				"scan pre-encryption detection event: %w",
				err,
			)
		}

		if err = json.Unmarshal(
			signalTypesJSON,
			&event.SignalTypes,
		); err != nil {
			return nil, fmt.Errorf(
				"decode detection event signals: %w",
				err,
			)
		}

		event.EventType =
			NormalizeConstant(
				event.EventType,
			)

		event.SourceType =
			NormalizeConstant(
				event.SourceType,
			)

		event.DetectionMethod =
			NormalizeConstant(
				event.DetectionMethod,
			)

		event.Severity =
			NormalizeConstant(
				event.Severity,
			)

		event.OccurredAt =
			event.OccurredAt.UTC()

		event.LinkedAt =
			event.LinkedAt.UTC()

		events = append(
			events,
			event,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate pre-encryption detection events: %w",
			err,
		)
	}

	return events, nil
}

func normalizeDetectionListFilter(
	filter DetectionListFilter,
) DetectionListFilter {
	filter.RiskLevel =
		NormalizeConstant(
			filter.RiskLevel,
		)

	filter.Classification =
		NormalizeConstant(
			filter.Classification,
		)

	filter.DetectionStage =
		NormalizeConstant(
			filter.DetectionStage,
		)

	filter.DetectionMethod =
		NormalizeConstant(
			filter.DetectionMethod,
		)

	filter.Status =
		NormalizeConstant(
			filter.Status,
		)

	filter.ActionStatus =
		NormalizeConstant(
			filter.ActionStatus,
		)

	filter.DeviceIdentifier =
		strings.TrimSpace(
			filter.DeviceIdentifier,
		)

	filter.ProcessName =
		strings.TrimSpace(
			filter.ProcessName,
		)

	if filter.DetectedFrom != nil {
		value := filter.DetectedFrom.UTC()
		filter.DetectedFrom = &value
	}

	if filter.DetectedTo != nil {
		value := filter.DetectedTo.UTC()
		filter.DetectedTo = &value
	}

	if filter.Limit <= 0 {
		filter.Limit =
			defaultDetectionPageSize
	}

	if filter.Limit >
		maximumDetectionPageSize {
		filter.Limit =
			maximumDetectionPageSize
	}

	if filter.Offset < 0 {
		filter.Offset = 0
	}

	return filter
}
