package honeytoken

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvestigationCaseNotFound = errors.New("investigation case not found")
	ErrCaseIncidentAlreadyLinked = errors.New("incident is already linked to an investigation case")
)

type InvestigationCaseRepository struct{ db *pgxpool.Pool }

func NewInvestigationCaseRepository(db *pgxpool.Pool) *InvestigationCaseRepository {
	return &InvestigationCaseRepository{db: db}
}

func (r *InvestigationCaseRepository) Create(ctx context.Context, item *InvestigationCase) error {
	const q = `INSERT INTO investigation_cases (id, organization_id, case_number, title, description, status, priority, lead_investigator_id, opened_by, opened_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING created_at, updated_at`
	if r == nil || r.db == nil {
		return errors.New("investigation case repository is unavailable")
	}
	return r.db.QueryRow(ctx, q, item.ID, item.OrganizationID, item.CaseNumber, item.Title, item.Description, item.Status, item.Priority, item.LeadInvestigatorID, item.OpenedBy, item.OpenedAt).Scan(&item.CreatedAt, &item.UpdatedAt)
}

func (r *InvestigationCaseRepository) Find(ctx context.Context, orgID, id uuid.UUID) (*InvestigationCase, error) {
	const q = `SELECT id, organization_id, case_number, title, description, status, priority, lead_investigator_id, opened_by, opened_at, closed_at, created_at, updated_at FROM investigation_cases WHERE id=$1 AND organization_id=$2 AND deleted_at IS NULL`
	item := &InvestigationCase{}
	err := r.db.QueryRow(ctx, q, id, orgID).Scan(&item.ID, &item.OrganizationID, &item.CaseNumber, &item.Title, &item.Description, &item.Status, &item.Priority, &item.LeadInvestigatorID, &item.OpenedBy, &item.OpenedAt, &item.ClosedAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvestigationCaseNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find investigation case: %w", err)
	}
	return item, nil
}

func (r *InvestigationCaseRepository) List(ctx context.Context, orgID uuid.UUID) ([]InvestigationCase, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New("investigation case repository is unavailable")
	}
	var total int64
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM investigation_cases WHERE organization_id=$1 AND deleted_at IS NULL`, orgID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count investigation cases: %w", err)
	}
	rows, err := r.db.Query(ctx, `SELECT id, organization_id, case_number, title, description, status, priority, lead_investigator_id, opened_by, opened_at, closed_at, created_at, updated_at FROM investigation_cases WHERE organization_id=$1 AND deleted_at IS NULL ORDER BY opened_at DESC`, orgID)
	if err != nil {
		return nil, 0, fmt.Errorf("list investigation cases: %w", err)
	}
	defer rows.Close()
	items := make([]InvestigationCase, 0)
	for rows.Next() {
		item := InvestigationCase{}
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.CaseNumber, &item.Title, &item.Description, &item.Status, &item.Priority, &item.LeadInvestigatorID, &item.OpenedBy, &item.OpenedAt, &item.ClosedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan investigation case: %w", err)
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (r *InvestigationCaseRepository) Update(ctx context.Context, item *InvestigationCase) error {
	const q = `UPDATE investigation_cases SET title=$3, description=$4, priority=$5, status=$6, closed_at=$7, updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND organization_id=$2 AND deleted_at IS NULL RETURNING updated_at`
	err := r.db.QueryRow(ctx, q, item.ID, item.OrganizationID, item.Title, item.Description, item.Priority, item.Status, item.ClosedAt).Scan(&item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvestigationCaseNotFound
	}
	if err != nil {
		return fmt.Errorf("update investigation case: %w", err)
	}
	return nil
}

func (r *InvestigationCaseRepository) LinkIncident(ctx context.Context, orgID, caseID, incidentID, actorID uuid.UUID) error {
	const q = `INSERT INTO investigation_case_incidents (case_id, incident_id, added_by) SELECT $1, i.id, $2 FROM incidents i INNER JOIN investigation_cases c ON c.id=$1 AND c.organization_id=$3 AND c.deleted_at IS NULL WHERE i.id=$4 AND i.organization_id=$3 AND i.deleted_at IS NULL`
	result, err := r.db.Exec(ctx, q, caseID, actorID, orgID, incidentID)
	if isIncidentConstraintViolation(err, "uq_investigation_case_incident") || isIncidentConstraintViolation(err, "investigation_case_incidents_pkey") {
		return ErrCaseIncidentAlreadyLinked
	}
	if err != nil {
		return fmt.Errorf("link incident to investigation case: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrIncidentNotFound
	}
	return nil
}

func (r *InvestigationCaseRepository) ListIncidents(ctx context.Context, orgID, caseID uuid.UUID) ([]Incident, error) {
	if _, err := r.Find(ctx, orgID, caseID); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT `+prefixIncidentColumns("i")+` FROM investigation_case_incidents ci INNER JOIN incidents i ON i.id=ci.incident_id WHERE ci.case_id=$1 AND i.organization_id=$2 AND i.deleted_at IS NULL ORDER BY ci.added_at ASC`, caseID, orgID)
	if err != nil {
		return nil, fmt.Errorf("list case incidents: %w", err)
	}
	defer rows.Close()
	items := make([]Incident, 0)
	for rows.Next() {
		item, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}
