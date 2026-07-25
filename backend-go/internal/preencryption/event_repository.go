package preencryption

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrFileEventNotFound = errors.New(
	"pre-encryption file event not found",
)

const (
	defaultRelatedEventLimit = 1000
	maximumRelatedEventLimit = 10000
)

const fileEventObservationColumns = `
	id,
	organization_id,
	department_id,
	protected_file_id,
	honeytoken_id,
	canary_file_id,
	event_code,
	source_type,
	event_type,
	event_source,
	detection_method,
	file_name,
	file_path,
	previous_file_path,
	file_extension,
	mime_type,
	file_size_before,
	file_size_after,
	previous_hash,
	current_hash,
	process_id,
	process_name,
	executable_path,
	parent_process_id,
	parent_process_name,
	command_line,
	device_name,
	device_identifier,
	severity,
	threat_score,
	is_suspicious,
	metadata,
	occurred_at
`

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(
	databasePool *pgxpool.Pool,
) *Repository {
	return &Repository{
		db: databasePool,
	}
}

func (r *Repository) GetFileEventObservation(
	ctx context.Context,
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
) (*FileEventObservation, error) {
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

	if fileEventID == uuid.Nil {
		return nil, errors.New(
			"file event ID is required",
		)
	}

	query := `
		SELECT ` + fileEventObservationColumns + `
		FROM file_events
		WHERE
			id = $1
			AND organization_id = $2;
	`

	event, err := scanFileEventObservation(
		r.db.QueryRow(
			ctx,
			query,
			fileEventID,
			organizationID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrFileEventNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"get pre-encryption file event: %w",
			err,
		)
	}

	return event, nil
}

func (r *Repository) ListRelatedFileEvents(
	ctx context.Context,
	organizationID uuid.UUID,
	deviceIdentifier *string,
	processID *int64,
	fallbackFilePath *string,
	windowStartedAt time.Time,
	windowEndedAt time.Time,
	limit int,
) ([]FileEventObservation, error) {
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

	if windowStartedAt.IsZero() ||
		windowEndedAt.IsZero() {
		return nil, errors.New(
			"detection window timestamps are required",
		)
	}

	windowStartedAt = windowStartedAt.UTC()
	windowEndedAt = windowEndedAt.UTC()

	if windowEndedAt.Before(windowStartedAt) {
		return nil, errors.New(
			"detection window end cannot be before start",
		)
	}

	deviceIdentifier =
		normalizeOptionalEventFilter(
			deviceIdentifier,
		)

	fallbackFilePath =
		normalizeOptionalEventFilter(
			fallbackFilePath,
		)

	if processID != nil && *processID < 0 {
		return nil, errors.New(
			"process ID cannot be negative",
		)
	}

	if deviceIdentifier == nil &&
		processID == nil &&
		fallbackFilePath == nil {
		return nil, errors.New(
			"device, process or file path filter is required",
		)
	}

	if limit <= 0 {
		limit = defaultRelatedEventLimit
	}

	if limit > maximumRelatedEventLimit {
		limit = maximumRelatedEventLimit
	}

	query := `
		SELECT ` + fileEventObservationColumns + `
		FROM file_events
		WHERE
			organization_id = $1
			AND occurred_at >= $2
			AND occurred_at <= $3
			AND event_type IN (
				'CREATED',
				'COPIED',
				'MOVED',
				'RENAMED',
				'MODIFIED',
				'ENCRYPTED',
				'DELETED',
				'EXTENSION_CHANGED',
				'PERMISSION_CHANGED',
				'HASH_CHANGED',
				'MULTIPLE_FILE_CHANGES'
			)
			AND (
				(
					$4::text IS NOT NULL
					AND device_identifier = $4
					AND (
						$5::bigint IS NULL
						OR process_id = $5
					)
				)
				OR (
					$4::text IS NULL
					AND $5::bigint IS NOT NULL
					AND process_id = $5
				)
				OR (
					$4::text IS NULL
					AND $5::bigint IS NULL
					AND $6::text IS NOT NULL
					AND file_path = $6
				)
			)
		ORDER BY
			occurred_at ASC,
			event_sequence ASC
		LIMIT $7;
	`

	rows, err := r.db.Query(
		ctx,
		query,
		organizationID,
		windowStartedAt,
		windowEndedAt,
		deviceIdentifier,
		processID,
		fallbackFilePath,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list related pre-encryption file events: %w",
			err,
		)
	}
	defer rows.Close()

	events := make(
		[]FileEventObservation,
		0,
	)

	for rows.Next() {
		event, scanErr :=
			scanFileEventObservation(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan related pre-encryption file event: %w",
				scanErr,
			)
		}

		events = append(
			events,
			*event,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate related pre-encryption file events: %w",
			err,
		)
	}

	return events, nil
}

type fileEventRowScanner interface {
	Scan(destinations ...any) error
}

func scanFileEventObservation(
	row fileEventRowScanner,
) (*FileEventObservation, error) {
	var event FileEventObservation

	err := row.Scan(
		&event.ID,
		&event.OrganizationID,
		&event.DepartmentID,
		&event.ProtectedFileID,
		&event.HoneytokenID,
		&event.CanaryFileID,
		&event.EventCode,
		&event.SourceType,
		&event.EventType,
		&event.EventSource,
		&event.DetectionMethod,
		&event.FileName,
		&event.FilePath,
		&event.PreviousFilePath,
		&event.FileExtension,
		&event.MimeType,
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
		&event.Metadata,
		&event.OccurredAt,
	)
	if err != nil {
		return nil, err
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

	return &event, nil
}

func normalizeOptionalEventFilter(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	normalized := strings.TrimSpace(
		*value,
	)

	if normalized == "" {
		return nil
	}

	return &normalized
}
