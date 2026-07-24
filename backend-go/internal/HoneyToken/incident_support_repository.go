package honeytoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// IncidentLinkedThreat contains safe threat information associated with an
// incident.
type IncidentLinkedThreat struct {
	ThreatID     uuid.UUID
	ThreatCode   string
	ThreatType   string
	Severity     string
	Status       string
	RelationType string
	AddedBy      *uuid.UUID
	AddedAt      time.Time
}

// LinkThreat links an organization threat to an incident and records the
// action in the incident timeline.
func (r *IncidentRepository) LinkThreat(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	threatID uuid.UUID,
	relationType string,
	actorUserID uuid.UUID,
) error {
	if r == nil || r.db == nil {
		return errors.New(
			"incident repository is unavailable",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"begin incident threat transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	_, err = findIncidentForUpdateTx(
		ctx,
		tx,
		organizationID,
		incidentID,
	)
	if err != nil {
		return err
	}

	commandTag, err := tx.Exec(
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
		incidentID,
		relationType,
		actorUserID,
		threatID,
		organizationID,
	)
	if err != nil {
		if isIncidentConstraintViolation(
			err,
			"uq_incident_threats_threat",
		) ||
			isIncidentConstraintViolation(
				err,
				"pk_incident_threats",
			) {
			return ErrIncidentThreatAlreadyLinked
		}

		return fmt.Errorf(
			"link threat to incident: %w",
			err,
		)
	}

	if commandTag.RowsAffected() == 0 {
		return ErrThreatNotFound
	}

	metadata, err := json.Marshal(
		map[string]any{
			"threat_id":     threatID.String(),
			"relation_type": relationType,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"build linked threat metadata: %w",
			err,
		)
	}

	err = insertIncidentTimelineTx(
		ctx,
		tx,
		&IncidentTimelineEntry{
			ID:             uuid.New(),
			IncidentID:     incidentID,
			OrganizationID: organizationID,
			EventType:      IncidentTimelineEventThreatLinked,
			Title:          "Threat linked to incident",
			ActorUserID: incidentUUIDPointer(
				actorUserID,
			),
			Metadata:   metadata,
			OccurredAt: time.Now().UTC(),
		},
	)
	if err != nil {
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit incident threat transaction: %w",
			err,
		)
	}

	return nil
}

// ListLinkedThreats returns threats associated with an organization incident.
func (r *IncidentRepository) ListLinkedThreats(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
) ([]IncidentLinkedThreat, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"incident repository is unavailable",
		)
	}

	if _, err := r.FindByID(
		ctx,
		organizationID,
		incidentID,
	); err != nil {
		return nil, err
	}

	const query = `
		SELECT
			t.id,
			t.threat_code,
			t.threat_type,
			t.severity,
			t.status,
			it.relation_type,
			it.added_by,
			it.added_at
		FROM incident_threats it
		INNER JOIN threats t
			ON t.id = it.threat_id
		INNER JOIN incidents i
			ON i.id = it.incident_id
		WHERE it.incident_id = $1
		  AND i.organization_id = $2
		  AND i.deleted_at IS NULL
		  AND t.deleted_at IS NULL
		ORDER BY
			CASE it.relation_type
				WHEN 'PRIMARY' THEN 1
				WHEN 'RELATED' THEN 2
				ELSE 3
			END,
			it.added_at ASC;
	`

	rows, err := r.db.Query(
		ctx,
		query,
		incidentID,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list incident threats: %w",
			err,
		)
	}
	defer rows.Close()

	threats := make(
		[]IncidentLinkedThreat,
		0,
	)

	for rows.Next() {
		var threat IncidentLinkedThreat

		err = rows.Scan(
			&threat.ThreatID,
			&threat.ThreatCode,
			&threat.ThreatType,
			&threat.Severity,
			&threat.Status,
			&threat.RelationType,
			&threat.AddedBy,
			&threat.AddedAt,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"scan incident threat: %w",
				err,
			)
		}

		threats = append(
			threats,
			threat,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate incident threats: %w",
			err,
		)
	}

	return threats, nil
}

// AddTimelineEntry inserts a validated organization incident activity.
func (r *IncidentRepository) AddTimelineEntry(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	entry *IncidentTimelineEntry,
) error {
	if r == nil || r.db == nil {
		return errors.New(
			"incident repository is unavailable",
		)
	}

	if entry == nil {
		return errors.New(
			"incident timeline entry is required",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"begin timeline transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	_, err = findIncidentForUpdateTx(
		ctx,
		tx,
		organizationID,
		incidentID,
	)
	if err != nil {
		return err
	}

	entry.ID = uuid.New()
	entry.IncidentID = incidentID
	entry.OrganizationID = organizationID

	if entry.OccurredAt.IsZero() {
		entry.OccurredAt = time.Now().UTC()
	}

	err = insertIncidentTimelineTx(
		ctx,
		tx,
		entry,
	)
	if err != nil {
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit timeline transaction: %w",
			err,
		)
	}

	return nil
}

// ListTimeline returns a paginated chronological incident history.
func (r *IncidentRepository) ListTimeline(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	eventType string,
	limit int,
	offset int,
) ([]IncidentTimelineEntry, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New(
			"incident repository is unavailable",
		)
	}

	if _, err := r.FindByID(
		ctx,
		organizationID,
		incidentID,
	); err != nil {
		return nil, 0, err
	}

	args := []any{
		incidentID,
		organizationID,
	}

	eventCondition := ""

	if eventType != "" {
		args = append(
			args,
			eventType,
		)

		eventCondition = fmt.Sprintf(
			" AND event_type = $%d",
			len(args),
		)
	}

	countQuery := `
		SELECT COUNT(*)
		FROM incident_timeline
		WHERE incident_id = $1
		  AND organization_id = $2` +
		eventCondition + `;
	`

	var total int64

	err := r.db.QueryRow(
		ctx,
		countQuery,
		args...,
	).Scan(
		&total,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"count incident timeline: %w",
			err,
		)
	}

	listArgs := append(
		[]any(nil),
		args...,
	)

	listArgs = append(
		listArgs,
		limit,
		offset,
	)

	limitPosition := len(listArgs) - 1
	offsetPosition := len(listArgs)

	listQuery := `
		SELECT
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
			occurred_at,
			created_at
		FROM incident_timeline
		WHERE incident_id = $1
		  AND organization_id = $2` +
		eventCondition + `
		ORDER BY occurred_at ASC, created_at ASC
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
			"list incident timeline: %w",
			err,
		)
	}
	defer rows.Close()

	entries := make(
		[]IncidentTimelineEntry,
		0,
	)

	for rows.Next() {
		entry, scanErr := scanIncidentTimelineEntry(
			rows,
		)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan incident timeline: %w",
				scanErr,
			)
		}

		entries = append(
			entries,
			*entry,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate incident timeline: %w",
			err,
		)
	}

	return entries, total, nil
}

func scanIncidentTimelineEntry(
	scanner incidentScanner,
) (*IncidentTimelineEntry, error) {
	entry := &IncidentTimelineEntry{}

	err := scanner.Scan(
		&entry.ID,
		&entry.IncidentID,
		&entry.OrganizationID,
		&entry.EventType,
		&entry.Title,
		&entry.Description,
		&entry.PreviousStatus,
		&entry.NewStatus,
		&entry.ActorUserID,
		&entry.Metadata,
		&entry.OccurredAt,
		&entry.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, err
	}

	return entry, nil
}
