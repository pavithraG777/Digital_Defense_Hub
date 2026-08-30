package dfir

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrDFIRRepositoryUnavailable = errors.New("DFIR repository is unavailable")

// Repository persists DFIR incidents, evidence, and timeline entries.
type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(databasePool *pgxpool.Pool) *Repository {
	if databasePool == nil {
		return nil
	}
	return &Repository{db: databasePool}
}

func (r *Repository) EnsureSchema(ctx context.Context) error {
	if r == nil || r.db == nil {
		return ErrDFIRRepositoryUnavailable
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS dfir_incidents (
			id UUID PRIMARY KEY,
			organization_id UUID NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'low',
			signals JSONB NOT NULL DEFAULT '[]'::jsonb,
			summary TEXT NOT NULL DEFAULT '',
			assessment JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			evidence_count INTEGER NOT NULL DEFAULT 0,
			timeline_count INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS dfir_evidence (
			id UUID PRIMARY KEY,
			incident_id UUID NOT NULL REFERENCES dfir_incidents(id) ON DELETE CASCADE,
			type TEXT NOT NULL,
			source TEXT NOT NULL,
			hash TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS dfir_timeline (
			id UUID PRIMARY KEY,
			incident_id UUID NOT NULL REFERENCES dfir_incidents(id) ON DELETE CASCADE,
			event_type TEXT NOT NULL,
			source TEXT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			metadata JSONB NOT NULL DEFAULT '{}'::jsonb
		);`,
	}

	for _, query := range queries {
		if _, err := r.db.Exec(ctx, query); err != nil {
			return fmt.Errorf("ensure dfir schema: %w", err)
		}
	}
	return nil
}

func (r *Repository) CreateIncident(ctx context.Context, incident *Incident) (*Incident, error) {
	if r == nil || r.db == nil {
		return nil, ErrDFIRRepositoryUnavailable
	}
	if incident == nil {
		return nil, ErrInvalidDFIRIncident
	}

	if incident.ID == uuid.Nil {
		incident.ID = uuid.New()
	}
	incident.CreatedAt = time.Now().UTC()
	incident.UpdatedAt = incident.CreatedAt

	_, err := r.db.Exec(ctx, `
		INSERT INTO dfir_incidents (
			id, organization_id, title, severity, signals, summary, assessment,
			created_at, updated_at, evidence_count, timeline_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`,
		incident.ID,
		incident.OrganizationID,
		incident.Title,
		incident.Severity,
		incident.Signals,
		incident.Summary,
		incident.Assessment,
		incident.CreatedAt,
		incident.UpdatedAt,
		incident.EvidenceCount,
		incident.TimelineCount,
	)
	if err != nil {
		return nil, fmt.Errorf("create dfir incident: %w", err)
	}
	return incident, nil
}

func (r *Repository) CreateEvidence(ctx context.Context, evidence *EvidenceArtifact) (*EvidenceArtifact, error) {
	if r == nil || r.db == nil {
		return nil, ErrDFIRRepositoryUnavailable
	}
	if evidence == nil {
		return nil, ErrInvalidDFIREvidence
	}
	if evidence.ID == uuid.Nil {
		evidence.ID = uuid.New()
	}
	if evidence.CreatedAt.IsZero() {
		evidence.CreatedAt = time.Now().UTC()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO dfir_evidence (id, incident_id, type, source, hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, evidence.ID, evidence.IncidentID, evidence.Type, evidence.Source, evidence.Hash, evidence.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create dfir evidence: %w", err)
	}

	_, err = r.db.Exec(ctx, `
		UPDATE dfir_incidents
		SET evidence_count = evidence_count + 1,
			updated_at = NOW()
		WHERE id = $1
	`, evidence.IncidentID)
	if err != nil {
		return nil, fmt.Errorf("increment dfir incident evidence: %w", err)
	}
	return evidence, nil
}

func (r *Repository) CreateTimelineEvent(ctx context.Context, event *TimelineEvent) (*TimelineEvent, error) {
	if r == nil || r.db == nil {
		return nil, ErrDFIRRepositoryUnavailable
	}
	if event == nil {
		return nil, ErrInvalidDFIRTimelineEvent
	}
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO dfir_timeline (id, incident_id, event_type, source, timestamp, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, event.ID, event.IncidentID, event.EventType, event.Source, event.Timestamp, event.Metadata)
	if err != nil {
		return nil, fmt.Errorf("create dfir timeline event: %w", err)
	}

	_, err = r.db.Exec(ctx, `
		UPDATE dfir_incidents
		SET timeline_count = timeline_count + 1,
			updated_at = NOW()
		WHERE id = $1
	`, event.IncidentID)
	if err != nil {
		return nil, fmt.Errorf("increment dfir incident timeline: %w", err)
	}
	return event, nil
}

func (r *Repository) GetIncidentSummary(ctx context.Context, incidentID uuid.UUID) (*IncidentSummary, error) {
	if r == nil || r.db == nil {
		return nil, ErrDFIRRepositoryUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrIncidentNotFound
	}

	var summary IncidentSummary
	var title, severity string
	var updatedAt sql.NullTime
	var evidenceCount, timelineCount int

	err := r.db.QueryRow(ctx, `
		SELECT title, severity, evidence_count, timeline_count, updated_at
		FROM dfir_incidents
		WHERE id = $1
	`, incidentID).Scan(&title, &severity, &evidenceCount, &timelineCount, &updatedAt)
	if err != nil {
		return nil, ErrIncidentNotFound
	}

	summary.IncidentID = incidentID
	summary.Title = title
	summary.Severity = severity
	summary.EvidenceCount = evidenceCount
	summary.TimelineCount = timelineCount
	if updatedAt.Valid {
		summary.LastUpdated = updatedAt.Time
	} else {
		summary.LastUpdated = time.Now().UTC()
	}
	return &summary, nil
}

func (r *Repository) GetIncident(ctx context.Context, incidentID uuid.UUID) (*Incident, error) {
	if r == nil || r.db == nil {
		return nil, ErrDFIRRepositoryUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIRIncident
	}

	incident := &Incident{}
	var updatedAt sql.NullTime
	err := r.db.QueryRow(ctx, `
		SELECT id, organization_id, title, severity, signals, summary, assessment,
		       created_at, updated_at, evidence_count, timeline_count
		FROM dfir_incidents
		WHERE id = $1
	`, incidentID).Scan(
		&incident.ID,
		&incident.OrganizationID,
		&incident.Title,
		&incident.Severity,
		&incident.Signals,
		&incident.Summary,
		&incident.Assessment,
		&incident.CreatedAt,
		&updatedAt,
		&incident.EvidenceCount,
		&incident.TimelineCount,
	)
	if err != nil {
		return nil, ErrIncidentNotFound
	}
	if updatedAt.Valid {
		incident.UpdatedAt = updatedAt.Time
	}
	return incident, nil
}

func (r *Repository) ListIncidents(ctx context.Context, organizationID uuid.UUID) ([]*Incident, error) {
	if r == nil || r.db == nil {
		return nil, ErrDFIRRepositoryUnavailable
	}
	if organizationID == uuid.Nil {
		return nil, ErrInvalidDFIRIncident
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, organization_id, title, severity, signals, summary, assessment,
		       created_at, updated_at, evidence_count, timeline_count
		FROM dfir_incidents
		WHERE organization_id = $1
		ORDER BY created_at DESC
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list dfir incidents: %w", err)
	}
	defer rows.Close()

	var results []*Incident
	for rows.Next() {
		incident := &Incident{}
		if err := rows.Scan(
			&incident.ID,
			&incident.OrganizationID,
			&incident.Title,
			&incident.Severity,
			&incident.Signals,
			&incident.Summary,
			&incident.Assessment,
			&incident.CreatedAt,
			&incident.UpdatedAt,
			&incident.EvidenceCount,
			&incident.TimelineCount,
		); err != nil {
			return nil, fmt.Errorf("scan dfir incident: %w", err)
		}
		results = append(results, incident)
	}
	return results, nil
}

func (r *Repository) ListEvidence(ctx context.Context, incidentID uuid.UUID) ([]*EvidenceArtifact, error) {
	if r == nil || r.db == nil {
		return nil, ErrDFIRRepositoryUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIREvidence
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, incident_id, type, source, hash, created_at
		FROM dfir_evidence
		WHERE incident_id = $1
		ORDER BY created_at DESC
	`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("list dfir evidence: %w", err)
	}
	defer rows.Close()

	var results []*EvidenceArtifact
	for rows.Next() {
		evidence := &EvidenceArtifact{}
		if err := rows.Scan(&evidence.ID, &evidence.IncidentID, &evidence.Type, &evidence.Source, &evidence.Hash, &evidence.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan dfir evidence: %w", err)
		}
		results = append(results, evidence)
	}
	return results, nil
}

func (r *Repository) ListTimeline(ctx context.Context, incidentID uuid.UUID) ([]*TimelineEvent, error) {
	if r == nil || r.db == nil {
		return nil, ErrDFIRRepositoryUnavailable
	}
	if incidentID == uuid.Nil {
		return nil, ErrInvalidDFIRTimelineEvent
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, incident_id, event_type, source, timestamp, metadata
		FROM dfir_timeline
		WHERE incident_id = $1
		ORDER BY timestamp ASC
	`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("list dfir timeline: %w", err)
	}
	defer rows.Close()

	var results []*TimelineEvent
	for rows.Next() {
		event := &TimelineEvent{}
		if err := rows.Scan(&event.ID, &event.IncidentID, &event.EventType, &event.Source, &event.Timestamp, &event.Metadata); err != nil {
			return nil, fmt.Errorf("scan dfir timeline event: %w", err)
		}
		results = append(results, event)
	}
	return results, nil
}
