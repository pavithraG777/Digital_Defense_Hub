package honeytoken

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

var ErrThreatNotFound = errors.New("threat not found")

const threatSelectColumns = `
	id,
	threat_sequence,
	threat_code,
	correlation_key,
	organization_id,
	department_id,
	primary_event_id AS primary_file_event_id,
	monitoring_rule_id,
	protected_file_id,
	honeytoken_id,
	canary_file_id,
	threat_type,
	threat_category,
	detection_method,
	title,
	description,
	severity,
	threat_score,
	confidence_score,
	classification,
	status,
	occurrence_count AS event_count,
	affected_file_count,
	first_detected_at,
	last_detected_at,
	source_process_name AS process_name,
	source_process_id AS process_id,
	NULL::text AS process_path,
	source_device_name AS device_name,
	source_device_identifier AS device_identifier,
	NULL::text AS source_ip_address,
	indicators,
	risk_factors,
	evidence_summary,
	recommended_action AS recommended_actions,
	mitigation_action AS containment_actions,
	resolution_notes,
	assigned_to,
	confirmed_by,
	resolved_by,
	confirmed_at,
	mitigated_at,
	resolved_at,
	created_at,
	updated_at,
	deleted_at
`

// ThreatRepository manages threat persistence and correlation.
type ThreatRepository struct {
	db *pgxpool.Pool
}

// ThreatCorrelationUpdate contains values updated when another file event is
// correlated with an existing threat.
type ThreatCorrelationUpdate struct {
	OccurredAt        time.Time
	Severity          string
	ThreatScore       int
	ConfidenceScore   float64
	Classification    string
	AffectedFileCount int
}

type threatScanner interface {
	Scan(dest ...any) error
}

func NewThreatRepository(db *pgxpool.Pool) *ThreatRepository {
	return &ThreatRepository{db: db}
}

// Create inserts a threat and links its primary file event atomically.
func (r *ThreatRepository) Create(
	ctx context.Context,
	threat *Threat,
) error {
	if r == nil || r.db == nil {
		return errors.New(
			"threat repository is unavailable",
		)
	}

	if threat == nil {
		return errors.New("threat is required")
	}

	if threat.PrimaryFileEventID == nil ||
		*threat.PrimaryFileEventID == uuid.Nil {
		return errors.New(
			"primary file event ID is required",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"begin create threat transaction: %w",
			err,
		)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const query = `
		INSERT INTO threats (
			id,
			threat_code,
			correlation_key,
			organization_id,
			department_id,
			primary_event_id,
			monitoring_rule_id,
			protected_file_id,
			honeytoken_id,
			canary_file_id,
			threat_type,
			threat_category,
			detection_method,
			title,
			description,
			severity,
			threat_score,
			confidence_score,
			classification,
			status,
			occurrence_count,
			affected_file_count,
			source_process_name,
			source_process_id,
			source_device_name,
			source_device_identifier,
			indicators,
			risk_factors,
			evidence_summary,
			recommended_action,
			mitigation_action,
			first_detected_at,
			last_detected_at,
			assigned_to,
			confirmed_by,
			confirmed_at,
			mitigated_at,
			resolved_at
		)
		VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
			$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
			$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,
			$31,$32,$33,$34,$35,$36,$37,$38
		)
		RETURNING
			threat_sequence,
			created_at,
			updated_at;
	`

	err = tx.QueryRow(
		ctx,
		query,
		threat.ID,
		threat.ThreatCode,
		threat.CorrelationKey,
		threat.OrganizationID,
		threat.DepartmentID,
		*threat.PrimaryFileEventID,
		threat.MonitoringRuleID,
		threat.ProtectedFileID,
		threat.HoneytokenID,
		threat.CanaryFileID,
		threat.ThreatType,
		threat.ThreatCategory,
		threat.DetectionMethod,
		threat.Title,
		threat.Description,
		threat.Severity,
		threat.ThreatScore,
		threat.ConfidenceScore,
		threat.Classification,
		threat.Status,
		threat.EventCount,
		threat.AffectedFileCount,
		threat.ProcessName,
		threat.ProcessID,
		threat.DeviceName,
		threat.DeviceIdentifier,
		threat.Indicators,
		threat.RiskFactors,
		threat.EvidenceSummary,
		threatRawMessageText(
			threat.RecommendedActions,
		),
		threatRawMessageText(
			threat.ContainmentActions,
		),
		threat.FirstDetectedAt,
		threat.LastDetectedAt,
		threat.AssignedTo,
		threat.ConfirmedBy,
		threat.ConfirmedAt,
		threat.MitigatedAt,
		threat.ResolvedAt,
	).Scan(
		&threat.ThreatSequence,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create threat: %w", err)
	}

	const relationQuery = `
		INSERT INTO threat_file_events (
			threat_id,
			file_event_id,
			relation_type
		)
		VALUES ($1, $2, $3)
		ON CONFLICT (threat_id, file_event_id) DO NOTHING;
	`

	_, err = tx.Exec(
		ctx,
		relationQuery,
		threat.ID,
		*threat.PrimaryFileEventID,
		ThreatEventRelationPrimary,
	)
	if err != nil {
		return fmt.Errorf(
			"link primary file event: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit create threat transaction: %w",
			err,
		)
	}

	return nil
}

// FindByID returns a threat belonging to the requested organization.
func (r *ThreatRepository) FindByID(
	ctx context.Context,
	organizationID uuid.UUID,
	threatID uuid.UUID,
) (*Threat, error) {
	query := `
		SELECT ` + threatSelectColumns + `
		FROM threats
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL
		LIMIT 1;
	`

	threat, err := scanThreat(
		r.db.QueryRow(ctx, query, threatID, organizationID),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrThreatNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find threat by ID: %w", err)
	}

	return threat, nil
}

// FindByCorrelationKey returns an existing active threat correlation.
func (r *ThreatRepository) FindByCorrelationKey(
	ctx context.Context,
	organizationID uuid.UUID,
	correlationKey string,
) (*Threat, error) {
	query := `
		SELECT ` + threatSelectColumns + `
		FROM threats
		WHERE
			organization_id = $1
			AND correlation_key = $2
			AND deleted_at IS NULL
		LIMIT 1;
	`

	threat, err := scanThreat(
		r.db.QueryRow(ctx, query, organizationID, correlationKey),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrThreatNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find threat by correlation key: %w", err)
	}

	return threat, nil
}

// CorrelateFileEvent links a new event and updates the existing threat.
// The returned boolean is false when the event was already linked.
func (r *ThreatRepository) CorrelateFileEvent(
	ctx context.Context,
	organizationID uuid.UUID,
	threatID uuid.UUID,
	fileEventID uuid.UUID,
	relationType string,
	update ThreatCorrelationUpdate,
) (bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin threat correlation transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const relationQuery = `
		INSERT INTO threat_file_events (
			threat_id,
			file_event_id,
			relation_type
		)
		SELECT $1, $2, $3
		WHERE EXISTS (
			SELECT 1
			FROM threats
			WHERE
				id = $1
				AND organization_id = $4
				AND deleted_at IS NULL
		)
		ON CONFLICT (threat_id, file_event_id) DO NOTHING;
	`

	result, err := tx.Exec(
		ctx,
		relationQuery,
		threatID,
		fileEventID,
		relationType,
		organizationID,
	)
	if err != nil {
		return false, fmt.Errorf("link correlated file event: %w", err)
	}

	if result.RowsAffected() == 0 {
		if err = tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("commit duplicate threat correlation: %w", err)
		}

		return false, nil
	}

	const updateQuery = `
		UPDATE threats
		SET
			occurrence_count = occurrence_count + 1,
			affected_file_count = GREATEST(
				affected_file_count,
				$3
			),
			last_detected_at = GREATEST(
				last_detected_at,
				$4
			),
			severity = $5,
			threat_score = $6,
			confidence_score = $7,
			classification = $8,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL;
	`

	result, err = tx.Exec(
		ctx,
		updateQuery,
		threatID,
		organizationID,
		update.AffectedFileCount,
		update.OccurredAt,
		update.Severity,
		update.ThreatScore,
		update.ConfidenceScore,
		update.Classification,
	)
	if err != nil {
		return false, fmt.Errorf("update correlated threat: %w", err)
	}

	if result.RowsAffected() == 0 {
		return false, ErrThreatNotFound
	}

	if err = tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit threat correlation transaction: %w", err)
	}

	return true, nil
}

// List returns organization-scoped threats and the total matching count.
func (r *ThreatRepository) List(
	ctx context.Context,
	filter ThreatFilter,
) ([]Threat, int64, error) {
	conditions := []string{
		"organization_id = $1",
		"deleted_at IS NULL",
	}
	args := []any{filter.OrganizationID}

	addCondition := func(condition string, value any) {
		args = append(args, value)
		conditions = append(
			conditions,
			fmt.Sprintf(condition, len(args)),
		)
	}

	if filter.DepartmentID != nil {
		addCondition("department_id = $%d", *filter.DepartmentID)
	}
	if filter.ThreatType != "" {
		addCondition("threat_type = $%d", filter.ThreatType)
	}
	if filter.Category != "" {
		addCondition("threat_category = $%d", filter.Category)
	}
	if filter.Severity != "" {
		addCondition("severity = $%d", filter.Severity)
	}
	if filter.Classification != "" {
		addCondition("classification = $%d", filter.Classification)
	}
	if filter.Status != "" {
		addCondition("status = $%d", filter.Status)
	}
	if filter.DetectionMethod != "" {
		addCondition("detection_method = $%d", filter.DetectionMethod)
	}
	if filter.Search != "" {
		searchValue := "%" + filter.Search + "%"

		args = append(args, searchValue, searchValue, searchValue)
		conditions = append(
			conditions,
			fmt.Sprintf(
				"(threat_code ILIKE $%d OR title ILIKE $%d OR COALESCE(description, '') ILIKE $%d)",
				len(args)-2,
				len(args)-1,
				len(args),
			),
		)
	}
	if filter.From != nil {
		addCondition("first_detected_at >= $%d", *filter.From)
	}
	if filter.To != nil {
		addCondition("first_detected_at <= $%d", *filter.To)
	}

	whereClause := strings.Join(conditions, " AND ")

	countQuery := `
		SELECT COUNT(*)
		FROM threats
		WHERE ` + whereClause + `;
	`

	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count threats: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	listArgs := append([]any{}, args...)
	listArgs = append(listArgs, limit, offset)
	limitPosition := len(listArgs) - 1
	offsetPosition := len(listArgs)

	listQuery := `
		SELECT ` + threatSelectColumns + `
		FROM threats
		WHERE ` + whereClause + `
		ORDER BY
			last_detected_at DESC,
			threat_sequence DESC
		LIMIT $` + fmt.Sprintf("%d", limitPosition) + `
		OFFSET $` + fmt.Sprintf("%d", offsetPosition) + `;
	`

	rows, err := r.db.Query(ctx, listQuery, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list threats: %w", err)
	}
	defer rows.Close()

	threats := make([]Threat, 0)
	for rows.Next() {
		threat, scanErr := scanThreat(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("scan listed threat: %w", scanErr)
		}

		threats = append(threats, *threat)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate threats: %w", err)
	}

	return threats, total, nil
}

// ListFileEvents returns all file events linked to a threat.
func (r *ThreatRepository) ListFileEvents(
	ctx context.Context,
	organizationID uuid.UUID,
	threatID uuid.UUID,
) ([]ThreatFileEvent, error) {
	const query = `
		SELECT
			tfe.threat_id,
			tfe.file_event_id,
			tfe.relation_type,
			tfe.added_at
		FROM threat_file_events tfe
		INNER JOIN threats t
			ON t.id = tfe.threat_id
		WHERE
			tfe.threat_id = $1
			AND t.organization_id = $2
			AND t.deleted_at IS NULL
		ORDER BY tfe.added_at ASC;
	`

	rows, err := r.db.Query(ctx, query, threatID, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list threat file events: %w", err)
	}
	defer rows.Close()

	relations := make([]ThreatFileEvent, 0)
	for rows.Next() {
		var relation ThreatFileEvent

		if err = rows.Scan(
			&relation.ThreatID,
			&relation.FileEventID,
			&relation.RelationType,
			&relation.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan threat file event: %w", err)
		}

		relations = append(relations, relation)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate threat file events: %w", err)
	}

	return relations, nil
}

// UpdateStatus updates the threat lifecycle while recording investigator
// identity and relevant lifecycle timestamps.
// UpdateStatus updates the threat lifecycle while recording investigator
// identity, resolution notes, and relevant lifecycle timestamps.
func (r *ThreatRepository) UpdateStatus(
	ctx context.Context,
	organizationID uuid.UUID,
	threatID uuid.UUID,
	status string,
	resolutionNotes *string,
	actorID uuid.UUID,
) (*Threat, error) {
	query := `
		UPDATE threats
		SET
			status = $3::varchar,
			resolution_notes = COALESCE(
				$4,
				resolution_notes
			),
			confirmed_by = CASE
				WHEN $3::varchar = 'CONFIRMED' THEN $5
				ELSE confirmed_by
			END,
			confirmed_at = CASE
				WHEN $3::varchar = 'CONFIRMED'
					THEN CURRENT_TIMESTAMP
				ELSE confirmed_at
			END,
			mitigated_at = CASE
				WHEN $3::varchar = 'MITIGATED'
					THEN CURRENT_TIMESTAMP
				ELSE mitigated_at
			END,
			resolved_by = CASE
				WHEN $3::varchar = 'RESOLVED' THEN $5
				ELSE resolved_by
			END,
			resolved_at = CASE
				WHEN $3::varchar = 'RESOLVED'
					THEN CURRENT_TIMESTAMP
				ELSE resolved_at
			END,
			updated_by = $5,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL
		RETURNING ` + threatSelectColumns + `;
	`

	threat, err := scanThreat(
		r.db.QueryRow(
			ctx,
			query,
			threatID,
			organizationID,
			status,
			resolutionNotes,
			actorID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrThreatNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"update threat status: %w",
			err,
		)
	}

	return threat, nil
}

// Assign assigns a threat to an investigator.
func (r *ThreatRepository) Assign(
	ctx context.Context,
	organizationID uuid.UUID,
	threatID uuid.UUID,
	assignedTo uuid.UUID,
) (*Threat, error) {
	query := `
		UPDATE threats
		SET
			assigned_to = $3,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL
		RETURNING ` + threatSelectColumns + `;
	`

	threat, err := scanThreat(
		r.db.QueryRow(
			ctx,
			query,
			threatID,
			organizationID,
			assignedTo,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrThreatNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("assign threat: %w", err)
	}

	return threat, nil
}

func scanThreat(scanner threatScanner) (*Threat, error) {
	var threat Threat
	var recommendedAction *string
	var mitigationAction *string

	err := scanner.Scan(
		&threat.ID,
		&threat.ThreatSequence,
		&threat.ThreatCode,
		&threat.CorrelationKey,
		&threat.OrganizationID,
		&threat.DepartmentID,
		&threat.PrimaryFileEventID,
		&threat.MonitoringRuleID,
		&threat.ProtectedFileID,
		&threat.HoneytokenID,
		&threat.CanaryFileID,
		&threat.ThreatType,
		&threat.ThreatCategory,
		&threat.DetectionMethod,
		&threat.Title,
		&threat.Description,
		&threat.Severity,
		&threat.ThreatScore,
		&threat.ConfidenceScore,
		&threat.Classification,
		&threat.Status,
		&threat.EventCount,
		&threat.AffectedFileCount,
		&threat.FirstDetectedAt,
		&threat.LastDetectedAt,
		&threat.ProcessName,
		&threat.ProcessID,
		&threat.ProcessPath,
		&threat.DeviceName,
		&threat.DeviceIdentifier,
		&threat.SourceIPAddress,
		&threat.Indicators,
		&threat.RiskFactors,
		&threat.EvidenceSummary,
		&recommendedAction,
		&mitigationAction,
		&threat.ResolutionNotes,
		&threat.AssignedTo,
		&threat.ConfirmedBy,
		&threat.ResolvedBy,
		&threat.ConfirmedAt,
		&threat.MitigatedAt,
		&threat.ResolvedAt,
		&threat.CreatedAt,
		&threat.UpdatedAt,
		&threat.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	if recommendedAction != nil {
		threat.RecommendedActions = append(
			threat.RecommendedActions[:0],
			(*recommendedAction)...,
		)
	}

	if mitigationAction != nil {
		threat.ContainmentActions = append(
			threat.ContainmentActions[:0],
			(*mitigationAction)...,
		)
	}

	return &threat, nil
}

// ClaimFileEventForThreatAnalysis atomically changes a queued event into the
// PROCESSING state. False means another worker has already handled or claimed
// the event.
func (r *ThreatRepository) ClaimFileEventForThreatAnalysis(
	ctx context.Context,
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
) (bool, error) {
	const query = `
		UPDATE file_events
		SET
			status = $3,
			processing_error = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND status IN ($4, $5, $6);
	`

	result, err := r.db.Exec(
		ctx,
		query,
		fileEventID,
		organizationID,
		FileEventStatusProcessing,
		FileEventStatusReceived,
		FileEventStatusQueued,
		FileEventStatusFailed,
	)
	if err != nil {
		return false, fmt.Errorf(
			"claim file event for threat analysis: %w",
			err,
		)
	}

	return result.RowsAffected() == 1, nil
}

// MarkFileEventThreatProcessed completes successful threat analysis.
func (r *ThreatRepository) MarkFileEventThreatProcessed(
	ctx context.Context,
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
) error {
	const query = `
		UPDATE file_events
		SET
			status = $3,
			processing_error = NULL,
			processed_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2
			AND status = $4;
	`

	result, err := r.db.Exec(
		ctx,
		query,
		fileEventID,
		organizationID,
		FileEventStatusProcessed,
		FileEventStatusProcessing,
	)
	if err != nil {
		return fmt.Errorf(
			"mark file event as processed: %w",
			err,
		)
	}

	if result.RowsAffected() == 0 {
		return ErrFileEventNotFound
	}

	return nil
}

// MarkFileEventThreatFailed records a safe processing error for retry and
// investigation.
func (r *ThreatRepository) MarkFileEventThreatFailed(
	ctx context.Context,
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
	processingError string,
) error {
	processingError = strings.TrimSpace(processingError)
	if processingError == "" {
		processingError = "Threat Engine processing failed"
	}

	const maximumProcessingErrorLength = 4000

	if len(processingError) > maximumProcessingErrorLength {
		processingError = processingError[:maximumProcessingErrorLength]
	}

	const query = `
		UPDATE file_events
		SET
			status = $3,
			processing_error = $4,
			processed_at = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE
			id = $1
			AND organization_id = $2;
	`

	result, err := r.db.Exec(
		ctx,
		query,
		fileEventID,
		organizationID,
		FileEventStatusFailed,
		processingError,
	)
	if err != nil {
		return fmt.Errorf(
			"mark file event as failed: %w",
			err,
		)
	}

	if result.RowsAffected() == 0 {
		return ErrFileEventNotFound
	}

	return nil
}

func threatRawMessageText(value []byte) *string {
	normalized := strings.TrimSpace(string(value))
	if normalized == "" {
		return nil
	}

	return &normalized
}
