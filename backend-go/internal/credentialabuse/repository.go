package credentialabuse

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CredentialEvent struct {
	ID             uuid.UUID              `json:"id"`
	OrganizationID uuid.UUID              `json:"organization_id"`
	UserID         uuid.UUID              `json:"user_id"`
	EventType      string                 `json:"event_type"`
	Metadata       map[string]interface{} `json:"metadata"`
	CreatedAt      time.Time              `json:"created_at"`
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

	queries := []string{
		`CREATE TABLE IF NOT EXISTS credential_events (
            id UUID PRIMARY KEY,
            organization_id UUID NOT NULL,
            user_id UUID NOT NULL,
            event_type TEXT NOT NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
			risk_score INTEGER NOT NULL DEFAULT 0,
			risk_level TEXT NOT NULL DEFAULT 'LOW',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );`,
		`ALTER TABLE credential_events ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE credential_events ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT 'LOW'`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(ctx, q); err != nil {
			return fmt.Errorf("ensure credential abuse schema: %w", err)
		}
	}

	return nil
}

func (r *Repository) CreateEvent(ctx context.Context, event *CredentialEvent, score int, level string) error {
	metadata, _ := json.Marshal(event.Metadata)
	_, err := r.db.Exec(ctx, `INSERT INTO credential_events(id,organization_id,user_id,event_type,metadata,risk_score,risk_level,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, event.ID, event.OrganizationID, event.UserID, event.EventType, metadata, score, level, event.CreatedAt)
	return err
}

func (r *Repository) RiskSummary(ctx context.Context, organizationID uuid.UUID) (map[string]any, error) {
	var total, critical, high, affected int
	var average float64
	err := r.db.QueryRow(ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE risk_level='CRITICAL'),COUNT(*) FILTER(WHERE risk_level='HIGH'),COUNT(DISTINCT user_id),COALESCE(AVG(risk_score),0) FROM credential_events WHERE organization_id=$1 AND created_at>=NOW()-INTERVAL '30 days'`, organizationID).Scan(&total, &critical, &high, &affected, &average)
	return map[string]any{"window_days": 30, "total_events": total, "critical_events": critical, "high_events": high, "affected_users": affected, "average_risk_score": average}, err
}

func (r *Repository) ListEvents(ctx context.Context, organizationID uuid.UUID, limit, offset int) ([]*CredentialEvent, error) {
	if r == nil || r.db == nil {
		return nil, nil
	}
	if organizationID == uuid.Nil {
		return nil, nil
	}

	rows, err := r.db.Query(ctx, `
        SELECT id, organization_id, user_id, event_type, metadata, created_at
        FROM credential_events
        WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
    `, organizationID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list credential events: %w", err)
	}
	defer rows.Close()

	var results []*CredentialEvent
	for rows.Next() {
		var e CredentialEvent
		var metadataBytes []byte
		if err := rows.Scan(&e.ID, &e.OrganizationID, &e.UserID, &e.EventType, &metadataBytes, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan credential event: %w", err)
		}
		if len(metadataBytes) > 0 {
			_ = json.Unmarshal(metadataBytes, &e.Metadata)
		}
		results = append(results, &e)
	}

	return results, nil
}
