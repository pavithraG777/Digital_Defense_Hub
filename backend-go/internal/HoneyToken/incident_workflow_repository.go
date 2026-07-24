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

var ErrIncidentInvestigatorNotFound = errors.New(
	"incident investigator not found",
)

// IncidentInvestigationUpdate contains optional investigation fields.
type IncidentInvestigationUpdate struct {
	InitialFindings    *string
	RootCause          *string
	ContainmentSummary *string
	ResolutionSummary  *string

	DataExposureSuspected *bool
	RansomwareSuspected   *bool
	DeviceIsolated        *bool
	EvidencePreserved     *bool

	AffectedRecordCount      *int64
	EstimatedFinancialImpact *float64
}

// UpdateStatus updates the incident lifecycle and creates an immutable
// timeline entry within the same transaction.
func (r *IncidentRepository) UpdateStatus(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	status string,
	containmentSummary *string,
	resolutionSummary *string,
	actorUserID uuid.UUID,
) (*Incident, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"incident repository is unavailable",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin incident status transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	currentIncident, err := findIncidentForUpdateTx(
		ctx,
		tx,
		organizationID,
		incidentID,
	)
	if err != nil {
		return nil, err
	}

	const query = `
		UPDATE incidents
		SET
			status = $3::varchar,
			containment_summary = COALESCE(
				$4::text,
				containment_summary
			),
			resolution_summary = COALESCE(
				$5::text,
				resolution_summary
			),
			investigation_started_at = CASE
				WHEN $3::varchar = 'INVESTIGATING'
					THEN COALESCE(
						investigation_started_at,
						CURRENT_TIMESTAMP
					)
				ELSE investigation_started_at
			END,
			contained_at = CASE
				WHEN $3::varchar = 'CONTAINED'
					THEN COALESCE(
						contained_at,
						CURRENT_TIMESTAMP
					)
				ELSE contained_at
			END,
			resolved_at = CASE
				WHEN $3::varchar = 'REOPENED'
					THEN NULL
				WHEN $3::varchar = 'RESOLVED'
					THEN COALESCE(
						resolved_at,
						CURRENT_TIMESTAMP
					)
				ELSE resolved_at
			END,
			closed_at = CASE
				WHEN $3::varchar = 'REOPENED'
					THEN NULL
				WHEN $3::varchar IN (
					'CLOSED',
					'CANCELLED'
				)
					THEN COALESCE(
						closed_at,
						CURRENT_TIMESTAMP
					)
				ELSE closed_at
			END,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		  AND organization_id = $2
		  AND deleted_at IS NULL
		RETURNING ` + incidentSelectColumns + `;
	`

	updatedIncident, err := scanIncident(
		tx.QueryRow(
			ctx,
			query,
			incidentID,
			organizationID,
			status,
			containmentSummary,
			resolutionSummary,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"update incident status: %w",
			err,
		)
	}

	metadata, err := json.Marshal(
		map[string]any{
			"previous_status":     currentIncident.Status,
			"new_status":          status,
			"containment_summary": containmentSummary,
			"resolution_summary":  resolutionSummary,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"build status timeline metadata: %w",
			err,
		)
	}

	now := time.Now().UTC()

	err = insertIncidentTimelineTx(
		ctx,
		tx,
		&IncidentTimelineEntry{
			ID:             uuid.New(),
			IncidentID:     incidentID,
			OrganizationID: organizationID,
			EventType:      IncidentTimelineEventStatusChanged,
			Title: fmt.Sprintf(
				"Incident status changed to %s",
				status,
			),
			PreviousStatus: stringPointer(
				currentIncident.Status,
			),
			NewStatus:   stringPointer(status),
			ActorUserID: incidentUUIDPointer(actorUserID),
			Metadata:    metadata,
			OccurredAt:  now,
		},
	)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit incident status transaction: %w",
			err,
		)
	}

	return updatedIncident, nil
}

// Assign assigns an incident to an investigator belonging to the same
// organization and records the assignment in the timeline.
func (r *IncidentRepository) Assign(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	investigatorID uuid.UUID,
	actorUserID uuid.UUID,
) (*Incident, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"incident repository is unavailable",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin incident assignment transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	currentIncident, err := findIncidentForUpdateTx(
		ctx,
		tx,
		organizationID,
		incidentID,
	)
	if err != nil {
		return nil, err
	}

	var investigatorExists bool

	err = tx.QueryRow(
		ctx,
		`
			SELECT EXISTS (
				SELECT 1
				FROM users
				WHERE id = $1
				  AND organization_id = $2
				  AND deleted_at IS NULL
			);
		`,
		investigatorID,
		organizationID,
	).Scan(
		&investigatorExists,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"validate incident investigator: %w",
			err,
		)
	}

	if !investigatorExists {
		return nil, ErrIncidentInvestigatorNotFound
	}

	newStatus := currentIncident.Status

	if currentIncident.Status == IncidentStatusOpen ||
		currentIncident.Status == IncidentStatusReopened {
		newStatus = IncidentStatusAssigned
	}

	query := `
		UPDATE incidents
		SET
			lead_investigator_id = $3,
			status = $4::varchar,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		  AND organization_id = $2
		  AND deleted_at IS NULL
		RETURNING ` + incidentSelectColumns + `;
	`

	updatedIncident, err := scanIncident(
		tx.QueryRow(
			ctx,
			query,
			incidentID,
			organizationID,
			investigatorID,
			newStatus,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"assign incident investigator: %w",
			err,
		)
	}

	metadata, err := json.Marshal(
		map[string]any{
			"lead_investigator_id": investigatorID.String(),
			"previous_status":      currentIncident.Status,
			"new_status":           newStatus,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"build assignment timeline metadata: %w",
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
			EventType:      IncidentTimelineEventAssigned,
			Title:          "Incident assigned to investigator",
			PreviousStatus: stringPointer(
				currentIncident.Status,
			),
			NewStatus:   stringPointer(newStatus),
			ActorUserID: incidentUUIDPointer(actorUserID),
			Metadata:    metadata,
			OccurredAt:  time.Now().UTC(),
		},
	)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit incident assignment transaction: %w",
			err,
		)
	}

	return updatedIncident, nil
}

// UpdateInvestigation updates findings, impact and containment information and
// records the modification in the incident timeline.
func (r *IncidentRepository) UpdateInvestigation(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
	update IncidentInvestigationUpdate,
	actorUserID uuid.UUID,
) (*Incident, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"incident repository is unavailable",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin investigation update transaction: %w",
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
		return nil, err
	}

	query := `
		UPDATE incidents
		SET
			initial_findings = COALESCE(
				$3::text,
				initial_findings
			),
			root_cause = COALESCE(
				$4::text,
				root_cause
			),
			containment_summary = COALESCE(
				$5::text,
				containment_summary
			),
			resolution_summary = COALESCE(
				$6::text,
				resolution_summary
			),
			data_exposure_suspected = COALESCE(
				$7::boolean,
				data_exposure_suspected
			),
			ransomware_suspected = COALESCE(
				$8::boolean,
				ransomware_suspected
			),
			device_isolated = COALESCE(
				$9::boolean,
				device_isolated
			),
			evidence_preserved = COALESCE(
				$10::boolean,
				evidence_preserved
			),
			affected_record_count = COALESCE(
				$11::bigint,
				affected_record_count
			),
			estimated_financial_impact = COALESCE(
				$12::numeric,
				estimated_financial_impact
			),
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
		  AND organization_id = $2
		  AND deleted_at IS NULL
		RETURNING ` + incidentSelectColumns + `;
	`

	updatedIncident, err := scanIncident(
		tx.QueryRow(
			ctx,
			query,
			incidentID,
			organizationID,
			update.InitialFindings,
			update.RootCause,
			update.ContainmentSummary,
			update.ResolutionSummary,
			update.DataExposureSuspected,
			update.RansomwareSuspected,
			update.DeviceIsolated,
			update.EvidencePreserved,
			update.AffectedRecordCount,
			update.EstimatedFinancialImpact,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"update incident investigation: %w",
			err,
		)
	}

	metadata, err := buildIncidentInvestigationMetadata(
		update,
	)
	if err != nil {
		return nil, err
	}

	err = insertIncidentTimelineTx(
		ctx,
		tx,
		&IncidentTimelineEntry{
			ID:             uuid.New(),
			IncidentID:     incidentID,
			OrganizationID: organizationID,
			EventType:      IncidentTimelineEventInvestigationUpdated,
			Title:          "Incident investigation updated",
			ActorUserID:    incidentUUIDPointer(actorUserID),
			Metadata:       metadata,
			OccurredAt:     time.Now().UTC(),
		},
	)
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit investigation update transaction: %w",
			err,
		)
	}

	return updatedIncident, nil
}

func findIncidentForUpdateTx(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
) (*Incident, error) {
	query := `
		SELECT ` + incidentSelectColumns + `
		FROM incidents
		WHERE id = $1
		  AND organization_id = $2
		  AND deleted_at IS NULL
		FOR UPDATE;
	`

	incident, err := scanIncident(
		tx.QueryRow(
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
			"lock incident for update: %w",
			err,
		)
	}

	return incident, nil
}

func buildIncidentInvestigationMetadata(
	update IncidentInvestigationUpdate,
) (json.RawMessage, error) {
	metadata := make(
		map[string]any,
	)

	if update.InitialFindings != nil {
		metadata["initial_findings_updated"] = true
	}

	if update.RootCause != nil {
		metadata["root_cause_updated"] = true
	}

	if update.ContainmentSummary != nil {
		metadata["containment_summary_updated"] = true
	}

	if update.ResolutionSummary != nil {
		metadata["resolution_summary_updated"] = true
	}

	if update.DataExposureSuspected != nil {
		metadata["data_exposure_suspected"] =
			*update.DataExposureSuspected
	}

	if update.RansomwareSuspected != nil {
		metadata["ransomware_suspected"] =
			*update.RansomwareSuspected
	}

	if update.DeviceIsolated != nil {
		metadata["device_isolated"] =
			*update.DeviceIsolated
	}

	if update.EvidencePreserved != nil {
		metadata["evidence_preserved"] =
			*update.EvidencePreserved
	}

	if update.AffectedRecordCount != nil {
		metadata["affected_record_count"] =
			*update.AffectedRecordCount
	}

	if update.EstimatedFinancialImpact != nil {
		metadata["estimated_financial_impact"] =
			*update.EstimatedFinancialImpact
	}

	encodedMetadata, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf(
			"build investigation timeline metadata: %w",
			err,
		)
	}

	return encodedMetadata, nil
}

func incidentUUIDPointer(
	value uuid.UUID,
) *uuid.UUID {
	return &value
}
