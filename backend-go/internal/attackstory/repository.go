package attackstory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Story struct {
	ID             uuid.UUID                `json:"id"`
	OrganizationID uuid.UUID                `json:"organization_id"`
	ThreatID       *uuid.UUID               `json:"threat_id,omitempty"`
	Title          string                   `json:"title"`
	Timeline       []map[string]interface{} `json:"timeline"`
	CreatedAt      time.Time                `json:"created_at"`
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(databasePool *pgxpool.Pool) (*Repository, error) {
	if databasePool == nil {
		return nil, fmt.Errorf("database pool required")
	}
	return &Repository{db: databasePool}, nil
}

func (r *Repository) EnsureSchema(ctx context.Context) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("repository unavailable")
	}

	q := `CREATE TABLE IF NOT EXISTS attack_stories (
        id UUID PRIMARY KEY,
        organization_id UUID NOT NULL,
		threat_id UUID,
		external_source_key TEXT,
        title TEXT NOT NULL,
        timeline JSONB NOT NULL DEFAULT '[]',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`

	if _, err := r.db.Exec(ctx, q); err != nil {
		return fmt.Errorf("ensure attackstory schema: %w", err)
	}
	if _, err := r.db.Exec(ctx, `ALTER TABLE attack_stories ADD COLUMN IF NOT EXISTS threat_id UUID`); err != nil {
		return fmt.Errorf("ensure attackstory threat link: %w", err)
	}
	if _, err := r.db.Exec(ctx, `ALTER TABLE attack_stories ADD COLUMN IF NOT EXISTS external_source_key TEXT`); err != nil {
		return fmt.Errorf("ensure attackstory external source key: %w", err)
	}
	if _, err := r.db.Exec(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS uq_attack_stories_organization_threat ON attack_stories (organization_id, threat_id) WHERE threat_id IS NOT NULL`); err != nil {
		return fmt.Errorf("ensure attackstory threat uniqueness: %w", err)
	}
	if _, err := r.db.Exec(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS uq_attack_stories_external_source ON attack_stories (organization_id, external_source_key) WHERE external_source_key IS NOT NULL`); err != nil {
		return fmt.Errorf("ensure attackstory external source uniqueness: %w", err)
	}

	return nil
}

// BackfillOrganization unifies historical threat/file-event narratives and
// versioned correlation-engine stories into the API's canonical store. Both
// imports are idempotent and preserve the original event timestamps.
func (r *Repository) BackfillOrganization(ctx context.Context, organizationID uuid.UUID) error {
	if r == nil || r.db == nil || organizationID == uuid.Nil {
		return fmt.Errorf("invalid attack story backfill context")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin attack story backfill: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO attack_stories (id, organization_id, threat_id, external_source_key, title, timeline, created_at)
		SELECT gen_random_uuid(), t.organization_id, t.id, 'threat:' || t.id::text,
		       'Automated Attack Story: ' || t.title,
		       COALESCE(jsonb_agg(e.payload ORDER BY e.occurred_at, e.sort_id), '[]'::jsonb),
		       t.first_detected_at
		FROM threats t
		CROSS JOIN LATERAL (
			SELECT f.occurred_at, f.id::text AS sort_id,
			       jsonb_build_object(
				 'event_id', f.id, 'timestamp', f.occurred_at, 'event_type', f.event_type,
				 'title', f.event_type || ' on ' || f.file_name, 'description', COALESCE(t.description, 'Threat-related file activity'),
				 'severity', f.severity, 'threat_code', t.threat_code, 'threat_type', t.threat_type,
				 'classification', t.classification, 'device_name', f.device_name,
				 'mitre_technique', CASE
				   WHEN t.threat_type IN ('CANARY_TRIGGERED','FILE_TAMPERING') THEN 'T1565'
				   WHEN t.threat_type IN ('MASS_FILE_RENAME','RANSOMWARE_ACTIVITY') THEN 'T1486'
				   WHEN t.threat_type='MASS_FILE_DELETION' THEN 'T1070.004' ELSE '' END
			   ) AS payload
			FROM threat_file_events tf JOIN file_events f ON f.id=tf.file_event_id
			WHERE tf.threat_id=t.id AND f.organization_id=t.organization_id
			UNION ALL
			SELECT i.updated_at, i.id::text,
			       jsonb_build_object(
				 'event_id', i.id, 'timestamp', i.updated_at, 'event_type', 'INCIDENT_' || i.status,
				 'title', i.incident_title, 'description', COALESCE(i.description, 'Incident linked to this threat'),
				 'severity', i.severity, 'incident_id', i.id, 'incident_number', i.incident_number,
				 'threat_code', t.threat_code, 'threat_type', t.threat_type
			   )
			FROM incident_threats it JOIN incidents i ON i.id=it.incident_id
			WHERE it.threat_id=t.id AND i.organization_id=t.organization_id
		) e
		WHERE t.organization_id=$1 AND t.deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM attack_stories s WHERE s.organization_id=t.organization_id AND s.threat_id=t.id)
		GROUP BY t.id, t.organization_id, t.title, t.description, t.threat_code, t.threat_type,
		         t.classification, t.first_detected_at`, organizationID)
	if err != nil {
		return fmt.Errorf("backfill threat attack stories: %w", err)
	}

	var correlationTablesAvailable bool
	if err = tx.QueryRow(ctx, `SELECT to_regclass('public.security_attack_stories') IS NOT NULL AND to_regclass('public.security_attack_story_versions') IS NOT NULL`).Scan(&correlationTablesAvailable); err != nil {
		return fmt.Errorf("check correlated attack story tables: %w", err)
	}
	if correlationTablesAvailable {
		_, err = tx.Exec(ctx, `
		INSERT INTO attack_stories (id, organization_id, external_source_key, title, timeline, created_at)
		SELECT gen_random_uuid(), s.organization_id, 'correlation:' || s.id::text,
		       s.title, COALESCE(v.timeline, '[]'::jsonb), s.created_at
		FROM security_attack_stories s
		JOIN security_attack_story_versions v ON v.story_id=s.id AND v.version=s.current_version
		WHERE s.organization_id=$1
		  AND NOT EXISTS (
			SELECT 1 FROM attack_stories a
			WHERE a.organization_id=s.organization_id AND a.external_source_key='correlation:' || s.id::text
		  )`, organizationID)
		if err != nil {
			return fmt.Errorf("backfill correlated attack stories: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit attack story backfill: %w", err)
	}
	return nil
}

// BackfillAllOrganizations makes historical stories available immediately at
// service startup instead of waiting for the first UI request.
func (r *Repository) BackfillAllOrganizations(ctx context.Context) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("attack story repository unavailable")
	}
	rows, err := r.db.Query(ctx, `SELECT id FROM organizations WHERE deleted_at IS NULL`)
	if err != nil {
		return fmt.Errorf("list organizations for attack story backfill: %w", err)
	}
	defer rows.Close()
	organizationIDs := make([]uuid.UUID, 0)
	for rows.Next() {
		var organizationID uuid.UUID
		if err = rows.Scan(&organizationID); err != nil {
			return fmt.Errorf("scan attack story organization: %w", err)
		}
		organizationIDs = append(organizationIDs, organizationID)
	}
	if err = rows.Err(); err != nil {
		return fmt.Errorf("iterate attack story organizations: %w", err)
	}
	for _, organizationID := range organizationIDs {
		if err = r.BackfillOrganization(ctx, organizationID); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) CreateStory(ctx context.Context, s *Story) error {
	if r == nil || r.db == nil || s == nil {
		return fmt.Errorf("invalid args")
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}

	timelineBytes, _ := json.Marshal(s.Timeline)

	_, err := r.db.Exec(ctx, `INSERT INTO attack_stories (id, organization_id, threat_id, title, timeline, created_at) VALUES ($1,$2,$3,$4,$5,$6)`, s.ID, s.OrganizationID, s.ThreatID, s.Title, timelineBytes, s.CreatedAt)
	if err != nil {
		return fmt.Errorf("create story: %w", err)
	}
	return nil
}

func (r *Repository) ListStories(ctx context.Context, organizationID uuid.UUID, limit, offset int) ([]*Story, error) {
	if r == nil || r.db == nil {
		return nil, nil
	}
	if organizationID == uuid.Nil {
		return nil, nil
	}

	rows, err := r.db.Query(ctx, `SELECT id, organization_id, threat_id, title, timeline, created_at FROM attack_stories WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, organizationID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list stories: %w", err)
	}
	defer rows.Close()

	var results []*Story
	for rows.Next() {
		var s Story
		var timelineBytes []byte
		if err := rows.Scan(&s.ID, &s.OrganizationID, &s.ThreatID, &s.Title, &timelineBytes, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan story: %w", err)
		}
		if len(timelineBytes) > 0 {
			_ = json.Unmarshal(timelineBytes, &s.Timeline)
		}
		results = append(results, &s)
	}

	return results, nil
}

// RecordThreatActivity creates one story per threat and appends every related
// event as a safe timeline entry.
func (r *Repository) RecordThreatActivity(ctx context.Context, organizationID, threatID, fileEventID uuid.UUID, title string, event map[string]interface{}, occurredAt time.Time) error {
	if r == nil || r.db == nil || organizationID == uuid.Nil || threatID == uuid.Nil || fileEventID == uuid.Nil {
		return fmt.Errorf("invalid attack story activity")
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	event["event_id"] = fileEventID.String()
	event["timestamp"] = occurredAt.UTC().Format(time.RFC3339Nano)
	timeline, err := json.Marshal([]map[string]interface{}{event})
	if err != nil {
		return fmt.Errorf("encode attack story activity: %w", err)
	}
	_, err = r.db.Exec(ctx, `INSERT INTO attack_stories (id, organization_id, threat_id, title, timeline, created_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (organization_id, threat_id) WHERE threat_id IS NOT NULL DO UPDATE SET timeline = attack_stories.timeline || EXCLUDED.timeline`, uuid.New(), organizationID, threatID, title, timeline, occurredAt)
	if err != nil {
		return fmt.Errorf("record attack story activity: %w", err)
	}
	return nil
}
