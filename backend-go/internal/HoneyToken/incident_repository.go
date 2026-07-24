package honeytoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrIncidentNotFound            = errors.New("incident not found")
	ErrIncidentNumberExists        = errors.New("incident number already exists")
	ErrIncidentThreatAlreadyLinked = errors.New("threat is already linked to an incident")
)

const incidentSelectColumns = `
	id,
	organization_id,
	department_id,
	incident_number,
	incident_title,
	description,
	incident_category,
	severity,
	priority,
	status,
	detection_source,
	affected_user_id,
	affected_device_name,
	affected_device_identifier,
	lead_investigator_id,
	reported_by,
	data_exposure_suspected,
	ransomware_suspected,
	device_isolated,
	evidence_preserved,
	affected_record_count,
	estimated_financial_impact,
	initial_findings,
	root_cause,
	containment_summary,
	resolution_summary,
	detected_at,
	reported_at,
	investigation_started_at,
	contained_at,
	resolved_at,
	closed_at,
	created_at,
	updated_at,
	deleted_at
`

// IncidentRepository manages tenant-isolated incident persistence.
type IncidentRepository struct {
	db *pgxpool.Pool
}

type incidentScanner interface {
	Scan(dest ...any) error
}

func NewIncidentRepository(
	db *pgxpool.Pool,
) *IncidentRepository {
	return &IncidentRepository{
		db: db,
	}
}

// Create inserts an incident and optionally links its originating threat.
// The incident, threat relationship and initial timeline entries are created
// in one database transaction.
func (r *IncidentRepository) Create(
	ctx context.Context,
	incident *Incident,
	linkedThreatID *uuid.UUID,
	actorUserID *uuid.UUID,
) error {
	if r == nil || r.db == nil {
		return errors.New("incident repository is unavailable")
	}

	if incident == nil {
		return errors.New("incident is required")
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"begin incident transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const query = `
		INSERT INTO incidents (
			id,
			organization_id,
			department_id,
			incident_number,
			incident_title,
			description,
			incident_category,
			severity,
			priority,
			status,
			detection_source,
			affected_user_id,
			affected_device_name,
			affected_device_identifier,
			lead_investigator_id,
			reported_by,
			data_exposure_suspected,
			ransomware_suspected,
			device_isolated,
			evidence_preserved,
			affected_record_count,
			estimated_financial_impact,
			initial_findings,
			root_cause,
			containment_summary,
			resolution_summary,
			detected_at,
			reported_at,
			investigation_started_at,
			contained_at,
			resolved_at,
			closed_at
		)
		VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,
			$9,$10,$11,$12,$13,$14,$15,$16,
			$17,$18,$19,$20,$21,$22,$23,$24,
			$25,$26,$27,$28,$29,$30,$31,$32
		)
		RETURNING
			created_at,
			updated_at;
	`

	err = tx.QueryRow(
		ctx,
		query,
		incident.ID,
		incident.OrganizationID,
		incident.DepartmentID,
		incident.IncidentNumber,
		incident.IncidentTitle,
		incident.Description,
		incident.IncidentCategory,
		incident.Severity,
		incident.Priority,
		incident.Status,
		incident.DetectionSource,
		incident.AffectedUserID,
		incident.AffectedDeviceName,
		incident.AffectedDeviceIdentifier,
		incident.LeadInvestigatorID,
		incident.ReportedBy,
		incident.DataExposureSuspected,
		incident.RansomwareSuspected,
		incident.DeviceIsolated,
		incident.EvidencePreserved,
		incident.AffectedRecordCount,
		incident.EstimatedFinancialImpact,
		incident.InitialFindings,
		incident.RootCause,
		incident.ContainmentSummary,
		incident.ResolutionSummary,
		incident.DetectedAt,
		incident.ReportedAt,
		incident.InvestigationStartedAt,
		incident.ContainedAt,
		incident.ResolvedAt,
		incident.ClosedAt,
	).Scan(
		&incident.CreatedAt,
		&incident.UpdatedAt,
	)
	if err != nil {
		if isIncidentConstraintViolation(
			err,
			"uq_incident_number",
		) {
			return ErrIncidentNumberExists
		}

		return fmt.Errorf(
			"create incident: %w",
			err,
		)
	}

	createdMetadata, err := json.Marshal(
		map[string]any{
			"incident_number":   incident.IncidentNumber,
			"incident_category": incident.IncidentCategory,
			"detection_source":  incident.DetectionSource,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"build incident timeline metadata: %w",
			err,
		)
	}

	err = insertIncidentTimelineTx(
		ctx,
		tx,
		&IncidentTimelineEntry{
			ID:             uuid.New(),
			IncidentID:     incident.ID,
			OrganizationID: incident.OrganizationID,
			EventType:      IncidentTimelineEventCreated,
			Title:          "Incident created",
			Description:    incident.Description,
			NewStatus:      stringPointer(incident.Status),
			ActorUserID:    actorUserID,
			Metadata:       createdMetadata,
			OccurredAt:     incident.ReportedAt,
		},
	)
	if err != nil {
		return err
	}

	if linkedThreatID != nil {
		commandTag, linkErr := tx.Exec(
			ctx,
			`
				INSERT INTO incident_threats (
					incident_id,
					threat_id,
					relation_type,
					added_by
				)
				SELECT
					$1,
					t.id,
					$2,
					$3
				FROM threats t
				WHERE t.id = $4
				  AND t.organization_id = $5
				  AND t.deleted_at IS NULL;
			`,
			incident.ID,
			IncidentThreatRelationPrimary,
			actorUserID,
			*linkedThreatID,
			incident.OrganizationID,
		)
		if linkErr != nil {
			if isIncidentConstraintViolation(
				linkErr,
				"uq_incident_threats_threat",
			) {
				return ErrIncidentThreatAlreadyLinked
			}

			return fmt.Errorf(
				"link incident threat: %w",
				linkErr,
			)
		}

		if commandTag.RowsAffected() == 0 {
			return ErrThreatNotFound
		}

		threatMetadata, marshalErr := json.Marshal(
			map[string]any{
				"threat_id":     linkedThreatID.String(),
				"relation_type": IncidentThreatRelationPrimary,
			},
		)
		if marshalErr != nil {
			return fmt.Errorf(
				"build threat timeline metadata: %w",
				marshalErr,
			)
		}

		err = insertIncidentTimelineTx(
			ctx,
			tx,
			&IncidentTimelineEntry{
				ID:             uuid.New(),
				IncidentID:     incident.ID,
				OrganizationID: incident.OrganizationID,
				EventType:      IncidentTimelineEventThreatLinked,
				Title:          "Threat linked to incident",
				ActorUserID:    actorUserID,
				Metadata:       threatMetadata,
				OccurredAt:     incident.ReportedAt,
			},
		)
		if err != nil {
			return err
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit incident transaction: %w",
			err,
		)
	}

	return nil
}

// FindByID returns an incident belonging to the requested organization.
func (r *IncidentRepository) FindByID(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
) (*Incident, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"incident repository is unavailable",
		)
	}

	query := `
		SELECT ` + incidentSelectColumns + `
		FROM incidents
		WHERE id = $1
		  AND organization_id = $2
		  AND deleted_at IS NULL;
	`

	incident, err := scanIncident(
		r.db.QueryRow(
			ctx,
			query,
			incidentID,
			organizationID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"find incident by ID: %w",
			err,
		)
	}

	return incident, nil
}

// FindByThreatID returns the incident already associated with a threat.
func (r *IncidentRepository) FindByThreatID(
	ctx context.Context,
	organizationID uuid.UUID,
	threatID uuid.UUID,
) (*Incident, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"incident repository is unavailable",
		)
	}

	query := `
		SELECT ` + prefixIncidentColumns("i") + `
		FROM incidents i
		INNER JOIN incident_threats it
			ON it.incident_id = i.id
		WHERE it.threat_id = $1
		  AND i.organization_id = $2
		  AND i.deleted_at IS NULL;
	`

	incident, err := scanIncident(
		r.db.QueryRow(
			ctx,
			query,
			threatID,
			organizationID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"find incident by threat: %w",
			err,
		)
	}

	return incident, nil
}

// List returns organization-scoped incidents and their total count.
func (r *IncidentRepository) List(
	ctx context.Context,
	filter IncidentFilter,
) ([]Incident, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New(
			"incident repository is unavailable",
		)
	}

	conditions := []string{
		"organization_id = $1",
		"deleted_at IS NULL",
	}

	args := []any{
		filter.OrganizationID,
	}

	addCondition := func(
		condition string,
		value any,
	) {
		args = append(args, value)

		conditions = append(
			conditions,
			fmt.Sprintf(
				condition,
				len(args),
			),
		)
	}

	if filter.DepartmentID != nil {
		addCondition(
			"department_id = $%d",
			*filter.DepartmentID,
		)
	}

	if filter.IncidentCategory != "" {
		addCondition(
			"incident_category = $%d",
			filter.IncidentCategory,
		)
	}

	if filter.Severity != "" {
		addCondition(
			"severity = $%d",
			filter.Severity,
		)
	}

	if filter.Priority != "" {
		addCondition(
			"priority = $%d",
			filter.Priority,
		)
	}

	if filter.Status != "" {
		addCondition(
			"status = $%d",
			filter.Status,
		)
	}

	if filter.DetectionSource != "" {
		addCondition(
			"detection_source = $%d",
			filter.DetectionSource,
		)
	}

	if filter.LeadInvestigatorID != nil {
		addCondition(
			"lead_investigator_id = $%d",
			*filter.LeadInvestigatorID,
		)
	}

	if filter.Search != "" {
		args = append(
			args,
			"%"+filter.Search+"%",
		)

		searchPlaceholder := fmt.Sprintf(
			"$%d",
			len(args),
		)

		conditions = append(
			conditions,
			fmt.Sprintf(
				`(
					incident_number ILIKE %s
					OR incident_title ILIKE %s
					OR COALESCE(description, '') ILIKE %s
				)`,
				searchPlaceholder,
				searchPlaceholder,
				searchPlaceholder,
			),
		)
	}

	if filter.From != nil {
		addCondition(
			"detected_at >= $%d",
			*filter.From,
		)
	}

	if filter.To != nil {
		addCondition(
			"detected_at <= $%d",
			*filter.To,
		)
	}

	whereClause := strings.Join(
		conditions,
		" AND ",
	)

	countQuery := `
		SELECT COUNT(*)
		FROM incidents
		WHERE ` + whereClause + `;
	`

	var total int64

	err := r.db.QueryRow(
		ctx,
		countQuery,
		args...,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"count incidents: %w",
			err,
		)
	}

	listArgs := append(
		[]any(nil),
		args...,
	)

	listArgs = append(
		listArgs,
		filter.Limit,
		filter.Offset,
	)

	limitPosition := len(listArgs) - 1
	offsetPosition := len(listArgs)

	listQuery := `
		SELECT ` + incidentSelectColumns + `
		FROM incidents
		WHERE ` + whereClause + `
		ORDER BY reported_at DESC, created_at DESC
		LIMIT $` + fmt.Sprint(limitPosition) + `
		OFFSET $` + fmt.Sprint(offsetPosition) + `;
	`

	rows, err := r.db.Query(
		ctx,
		listQuery,
		listArgs...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list incidents: %w",
			err,
		)
	}
	defer rows.Close()

	incidents := make(
		[]Incident,
		0,
	)

	for rows.Next() {
		incident, scanErr := scanIncident(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan incident list: %w",
				scanErr,
			)
		}

		incidents = append(
			incidents,
			*incident,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate incident list: %w",
			err,
		)
	}

	return incidents, total, nil
}

func scanIncident(
	scanner incidentScanner,
) (*Incident, error) {
	incident := &Incident{}

	err := scanner.Scan(
		&incident.ID,
		&incident.OrganizationID,
		&incident.DepartmentID,
		&incident.IncidentNumber,
		&incident.IncidentTitle,
		&incident.Description,
		&incident.IncidentCategory,
		&incident.Severity,
		&incident.Priority,
		&incident.Status,
		&incident.DetectionSource,
		&incident.AffectedUserID,
		&incident.AffectedDeviceName,
		&incident.AffectedDeviceIdentifier,
		&incident.LeadInvestigatorID,
		&incident.ReportedBy,
		&incident.DataExposureSuspected,
		&incident.RansomwareSuspected,
		&incident.DeviceIsolated,
		&incident.EvidencePreserved,
		&incident.AffectedRecordCount,
		&incident.EstimatedFinancialImpact,
		&incident.InitialFindings,
		&incident.RootCause,
		&incident.ContainmentSummary,
		&incident.ResolutionSummary,
		&incident.DetectedAt,
		&incident.ReportedAt,
		&incident.InvestigationStartedAt,
		&incident.ContainedAt,
		&incident.ResolvedAt,
		&incident.ClosedAt,
		&incident.CreatedAt,
		&incident.UpdatedAt,
		&incident.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	return incident, nil
}

func insertIncidentTimelineTx(
	ctx context.Context,
	tx pgx.Tx,
	entry *IncidentTimelineEntry,
) error {
	if entry == nil {
		return errors.New(
			"incident timeline entry is required",
		)
	}

	metadata := entry.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}

	const query = `
		INSERT INTO incident_timeline (
			id,
			incident_id,
			organization_id,
			event_type,
			title,
			description,
			previous_status,
			new_status,
			actor_user_id,
			metadata,
			occurred_at
		)
		VALUES (
			$1,$2,$3,$4,$5,$6,
			$7,$8,$9,$10,$11
		)
		RETURNING created_at;
	`

	err := tx.QueryRow(
		ctx,
		query,
		entry.ID,
		entry.IncidentID,
		entry.OrganizationID,
		entry.EventType,
		entry.Title,
		entry.Description,
		entry.PreviousStatus,
		entry.NewStatus,
		entry.ActorUserID,
		metadata,
		entry.OccurredAt,
	).Scan(
		&entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"create incident timeline entry: %w",
			err,
		)
	}

	return nil
}

func prefixIncidentColumns(
	alias string,
) string {
	columns := strings.Split(
		incidentSelectColumns,
		",",
	)

	for index := range columns {
		column := strings.TrimSpace(
			columns[index],
		)

		columns[index] = alias + "." + column
	}

	return strings.Join(
		columns,
		", ",
	)
}

func isIncidentConstraintViolation(
	err error,
	constraintName string,
) bool {
	var pgError *pgconn.PgError

	if !errors.As(err, &pgError) {
		return false
	}

	return pgError.Code == "23505" &&
		pgError.ConstraintName == constraintName
}

func stringPointer(
	value string,
) *string {
	return &value
}
