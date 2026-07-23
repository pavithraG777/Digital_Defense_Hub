package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrFileEventNotFound              = errors.New("file event not found")
	ErrFileEventDuplicate             = errors.New("duplicate file event")
	ErrFileEventCodeExists            = errors.New("file event code already exists")
	ErrFileEventDepartmentNotFound    = errors.New("file event department not found")
	ErrFileEventRuleNotFound          = errors.New("file monitoring rule not found")
	ErrFileEventProtectedFileNotFound = errors.New("protected file reference not found")
	ErrFileEventHoneytokenNotFound    = errors.New("honeytoken reference not found")
	ErrFileEventCanaryNotFound        = errors.New("canary file reference not found")
	ErrFileEventUserNotFound          = errors.New("application user reference not found")
)

const fileEventSelectColumns = `
	id,
	event_sequence,
	event_code,
	event_fingerprint,
	organization_id,
	department_id,
	monitoring_rule_id,
	protected_file_id,
	honeytoken_id,
	canary_file_id,
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
	hash_algorithm,
	process_id,
	process_name,
	executable_path,
	parent_process_id,
	parent_process_name,
	command_line,
	process_hash,
	system_username,
	application_user_id,
	device_name,
	device_identifier,
	ip_address::text,
	mac_address,
	severity,
	threat_score,
	is_suspicious,
	status,
	processing_error,
	evidence_copy_path,
	evidence_hash,
	raw_event,
	metadata,
	occurred_at,
	received_at,
	processed_at,
	created_at,
	updated_at
`

type FileEventListFilter struct {
	OrganizationID uuid.UUID
	DepartmentID   *uuid.UUID
	SourceType     string
	EventType      string
	Severity       string
	Status         string
	IsSuspicious   *bool
	From           *time.Time
	To             *time.Time
	Limit          int
	Offset         int
}

// CreateFileEvent stores an append-only forensic event.
func (r *Repository) CreateFileEvent(
	ctx context.Context,
	event *FileEvent,
) error {
	if event == nil {
		return errors.New("file event is required")
	}

	if event.ID == uuid.Nil {
		return errors.New("file event ID is required")
	}

	if event.OrganizationID == uuid.Nil {
		return errors.New("organization ID is required")
	}

	const query = `
		INSERT INTO file_events (
			id,
			event_code,
			event_fingerprint,
			organization_id,
			department_id,
			monitoring_rule_id,
			protected_file_id,
			honeytoken_id,
			canary_file_id,
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
			hash_algorithm,
			process_id,
			process_name,
			executable_path,
			parent_process_id,
			parent_process_name,
			command_line,
			process_hash,
			system_username,
			application_user_id,
			device_name,
			device_identifier,
			ip_address,
			mac_address,
			severity,
			threat_score,
			is_suspicious,
			status,
			processing_error,
			evidence_copy_path,
			evidence_hash,
			raw_event,
			metadata,
			occurred_at,
			processed_at,
			received_at,
			created_at,
			updated_at
		)
		VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
			$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
			$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,
			$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,
			$41,$42,$43,$44,$45,$46,$47,
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP,
			CURRENT_TIMESTAMP
		)
		RETURNING
			event_sequence,
			received_at,
			created_at,
			updated_at;
	`

	err := r.db.QueryRow(
		ctx,
		query,
		event.ID,
		event.EventCode,
		event.EventFingerprint,
		event.OrganizationID,
		event.DepartmentID,
		event.MonitoringRuleID,
		event.ProtectedFileID,
		event.HoneytokenID,
		event.CanaryFileID,
		event.SourceType,
		event.EventType,
		event.EventSource,
		event.DetectionMethod,
		event.FileName,
		event.FilePath,
		event.PreviousFilePath,
		event.FileExtension,
		event.MimeType,
		event.FileSizeBefore,
		event.FileSizeAfter,
		event.PreviousHash,
		event.CurrentHash,
		event.HashAlgorithm,
		event.ProcessID,
		event.ProcessName,
		event.ExecutablePath,
		event.ParentProcessID,
		event.ParentProcessName,
		event.CommandLine,
		event.ProcessHash,
		event.SystemUsername,
		event.ApplicationUserID,
		event.DeviceName,
		event.DeviceIdentifier,
		event.IPAddress,
		event.MACAddress,
		event.Severity,
		event.ThreatScore,
		event.IsSuspicious,
		event.Status,
		event.ProcessingError,
		event.EvidenceCopyPath,
		event.EvidenceHash,
		event.RawEvent,
		event.Metadata,
		event.OccurredAt,
		event.ProcessedAt,
	).Scan(
		&event.EventSequence,
		&event.ReceivedAt,
		&event.CreatedAt,
		&event.UpdatedAt,
	)
	if err != nil {
		return mapFileEventWriteError(
			err,
			"failed to create file event",
		)
	}

	return nil
}

// FindFileEventByID returns one tenant-isolated forensic event.
func (r *Repository) FindFileEventByID(
	ctx context.Context,
	organizationID uuid.UUID,
	eventID uuid.UUID,
) (*FileEvent, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}

	if eventID == uuid.Nil {
		return nil, errors.New("file event ID is required")
	}

	query := `
		SELECT ` + fileEventSelectColumns + `
		FROM file_events
		WHERE
			id = $1
			AND organization_id = $2
		LIMIT 1;
	`

	event, err := scanFileEvent(
		r.db.QueryRow(
			ctx,
			query,
			eventID,
			organizationID,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFileEventNotFound
		}

		return nil, fmt.Errorf(
			"failed to find file event: %w",
			err,
		)
	}

	return event, nil
}

// FindFileEventByFingerprint supports idempotent watcher submissions.
func (r *Repository) FindFileEventByFingerprint(
	ctx context.Context,
	organizationID uuid.UUID,
	eventFingerprint string,
) (*FileEvent, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}

	eventFingerprint = strings.TrimSpace(
		eventFingerprint,
	)
	if eventFingerprint == "" {
		return nil, errors.New(
			"event fingerprint is required",
		)
	}

	query := `
		SELECT ` + fileEventSelectColumns + `
		FROM file_events
		WHERE
			organization_id = $1
			AND event_fingerprint = $2
		LIMIT 1;
	`

	event, err := scanFileEvent(
		r.db.QueryRow(
			ctx,
			query,
			organizationID,
			eventFingerprint,
		),
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFileEventNotFound
		}

		return nil, fmt.Errorf(
			"failed to find file event by fingerprint: %w",
			err,
		)
	}

	return event, nil
}

// ListFileEvents returns a paginated tenant-isolated event timeline.
func (r *Repository) ListFileEvents(
	ctx context.Context,
	filter FileEventListFilter,
) ([]FileEvent, int64, error) {
	filter = normalizeFileEventListFilter(filter)

	if filter.OrganizationID == uuid.Nil {
		return nil, 0, errors.New(
			"organization ID is required",
		)
	}

	whereClause, queryArguments :=
		buildFileEventFilter(filter)

	countQuery := `
		SELECT COUNT(*)
		FROM file_events
		WHERE ` + whereClause + `;
	`

	var total int64

	if err := r.db.QueryRow(
		ctx,
		countQuery,
		queryArguments...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf(
			"failed to count file events: %w",
			err,
		)
	}

	dataArguments := append(
		[]any(nil),
		queryArguments...,
	)

	limitPosition := len(dataArguments) + 1
	offsetPosition := len(dataArguments) + 2

	dataArguments = append(
		dataArguments,
		filter.Limit,
		filter.Offset,
	)

	dataQuery := fmt.Sprintf(`
		SELECT %s
		FROM file_events
		WHERE %s
		ORDER BY
			occurred_at DESC,
			event_sequence DESC
		LIMIT $%d
		OFFSET $%d;
	`,
		fileEventSelectColumns,
		whereClause,
		limitPosition,
		offsetPosition,
	)

	rows, err := r.db.Query(
		ctx,
		dataQuery,
		dataArguments...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"failed to list file events: %w",
			err,
		)
	}
	defer rows.Close()

	events := make([]FileEvent, 0, filter.Limit)

	for rows.Next() {
		event, scanErr := scanFileEvent(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"failed to scan file event: %w",
				scanErr,
			)
		}

		events = append(events, *event)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"failed while reading file events: %w",
			err,
		)
	}

	return events, total, nil
}

// ValidateFileEventRelations prevents cross-organization references.
func (r *Repository) ValidateFileEventRelations(
	ctx context.Context,
	organizationID uuid.UUID,
	departmentID *uuid.UUID,
	monitoringRuleID *uuid.UUID,
	protectedFileID *uuid.UUID,
	honeytokenID *uuid.UUID,
	canaryFileID *uuid.UUID,
	applicationUserID *uuid.UUID,
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
					FROM file_monitoring_rules
					WHERE id = $3
					  AND organization_id = $1
					  AND deleted_at IS NULL
				)
			),
			(
				$4::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM protected_files
					WHERE id = $4
					  AND organization_id = $1
					  AND deleted_at IS NULL
				)
			),
			(
				$5::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM honeytokens
					WHERE id = $5
					  AND organization_id = $1
					  AND deleted_at IS NULL
				)
			),
			(
				$6::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM canary_files
					WHERE id = $6
					  AND organization_id = $1
					  AND deleted_at IS NULL
				)
			),
			(
				$7::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM users
					WHERE id = $7
					  AND organization_id = $1
				)
			);
	`

	var (
		departmentValid    bool
		ruleValid          bool
		protectedFileValid bool
		honeytokenValid    bool
		canaryValid        bool
		userValid          bool
	)

	err := r.db.QueryRow(
		ctx,
		query,
		organizationID,
		departmentID,
		monitoringRuleID,
		protectedFileID,
		honeytokenID,
		canaryFileID,
		applicationUserID,
	).Scan(
		&departmentValid,
		&ruleValid,
		&protectedFileValid,
		&honeytokenValid,
		&canaryValid,
		&userValid,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to validate file event relations: %w",
			err,
		)
	}

	switch {
	case !departmentValid:
		return ErrFileEventDepartmentNotFound

	case !ruleValid:
		return ErrFileEventRuleNotFound

	case !protectedFileValid:
		return ErrFileEventProtectedFileNotFound

	case !honeytokenValid:
		return ErrFileEventHoneytokenNotFound

	case !canaryValid:
		return ErrFileEventCanaryNotFound

	case !userValid:
		return ErrFileEventUserNotFound

	default:
		return nil
	}
}

func normalizeFileEventListFilter(
	filter FileEventListFilter,
) FileEventListFilter {
	if filter.Limit <= 0 {
		filter.Limit = 20
	}

	if filter.Limit > 100 {
		filter.Limit = 100
	}

	if filter.Offset < 0 {
		filter.Offset = 0
	}

	filter.SourceType = strings.TrimSpace(
		filter.SourceType,
	)
	filter.EventType = strings.TrimSpace(
		filter.EventType,
	)
	filter.Severity = strings.TrimSpace(
		filter.Severity,
	)
	filter.Status = strings.TrimSpace(
		filter.Status,
	)

	return filter
}

func buildFileEventFilter(
	filter FileEventListFilter,
) (string, []any) {
	conditions := []string{
		"organization_id = $1",
	}

	arguments := []any{
		filter.OrganizationID,
	}

	if filter.DepartmentID != nil {
		arguments = append(
			arguments,
			filter.DepartmentID,
		)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"department_id = $%d",
				len(arguments),
			),
		)
	}

	if filter.SourceType != "" {
		arguments = append(
			arguments,
			filter.SourceType,
		)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"source_type = $%d",
				len(arguments),
			),
		)
	}

	if filter.EventType != "" {
		arguments = append(
			arguments,
			filter.EventType,
		)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"event_type = $%d",
				len(arguments),
			),
		)
	}

	if filter.Severity != "" {
		arguments = append(
			arguments,
			filter.Severity,
		)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"severity = $%d",
				len(arguments),
			),
		)
	}

	if filter.Status != "" {
		arguments = append(
			arguments,
			filter.Status,
		)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"status = $%d",
				len(arguments),
			),
		)
	}

	if filter.IsSuspicious != nil {
		arguments = append(
			arguments,
			*filter.IsSuspicious,
		)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"is_suspicious = $%d",
				len(arguments),
			),
		)
	}

	if filter.From != nil {
		arguments = append(
			arguments,
			*filter.From,
		)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"occurred_at >= $%d",
				len(arguments),
			),
		)
	}

	if filter.To != nil {
		arguments = append(
			arguments,
			*filter.To,
		)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"occurred_at <= $%d",
				len(arguments),
			),
		)
	}

	return strings.Join(
		conditions,
		" AND ",
	), arguments
}

type fileEventScanner interface {
	Scan(destinations ...any) error
}

func scanFileEvent(
	scanner fileEventScanner,
) (*FileEvent, error) {
	var event FileEvent

	err := scanner.Scan(
		&event.ID,
		&event.EventSequence,
		&event.EventCode,
		&event.EventFingerprint,
		&event.OrganizationID,
		&event.DepartmentID,
		&event.MonitoringRuleID,
		&event.ProtectedFileID,
		&event.HoneytokenID,
		&event.CanaryFileID,
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
		&event.HashAlgorithm,
		&event.ProcessID,
		&event.ProcessName,
		&event.ExecutablePath,
		&event.ParentProcessID,
		&event.ParentProcessName,
		&event.CommandLine,
		&event.ProcessHash,
		&event.SystemUsername,
		&event.ApplicationUserID,
		&event.DeviceName,
		&event.DeviceIdentifier,
		&event.IPAddress,
		&event.MACAddress,
		&event.Severity,
		&event.ThreatScore,
		&event.IsSuspicious,
		&event.Status,
		&event.ProcessingError,
		&event.EvidenceCopyPath,
		&event.EvidenceHash,
		&event.RawEvent,
		&event.Metadata,
		&event.OccurredAt,
		&event.ReceivedAt,
		&event.ProcessedAt,
		&event.CreatedAt,
		&event.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &event, nil
}

func mapFileEventWriteError(
	err error,
	contextMessage string,
) error {
	var databaseError *pgconn.PgError

	if errors.As(err, &databaseError) &&
		databaseError.Code == "23505" {
		switch databaseError.ConstraintName {
		case "uq_file_event_fingerprint":
			return ErrFileEventDuplicate

		case "uq_file_event_code":
			return ErrFileEventCodeExists
		}
	}

	return fmt.Errorf("%s: %w", contextMessage, err)
}
