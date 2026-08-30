package lateralmovement

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Alert struct {
	ID             uuid.UUID              `json:"id"`
	OrganizationID uuid.UUID              `json:"organization_id"`
	DeviceID       string                 `json:"device_id"`
	AlertType      string                 `json:"alert_type"`
	Details        map[string]interface{} `json:"details"`
	CreatedAt      time.Time              `json:"created_at"`
}

func (r *Repository) CreateAlert(ctx context.Context, alert *Alert) error {
	if alert == nil || alert.OrganizationID == uuid.Nil {
		return fmt.Errorf("invalid alert")
	}
	details, _ := json.Marshal(alert.Details)
	_, err := r.db.Exec(ctx, `INSERT INTO lateral_movement_alerts(id,organization_id,device_id,alert_type,details,created_at) VALUES($1,$2,$3,$4,$5,$6)`, alert.ID, alert.OrganizationID, alert.DeviceID, alert.AlertType, details, alert.CreatedAt)
	return err
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
		`CREATE TABLE IF NOT EXISTS lateral_movement_alerts (
            id UUID PRIMARY KEY,
            organization_id UUID NOT NULL,
            device_id TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            details JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(ctx, q); err != nil {
			return fmt.Errorf("ensure lateral movement schema: %w", err)
		}
	}

	return nil
}

func (r *Repository) ListAlerts(ctx context.Context, organizationID uuid.UUID, limit, offset int) ([]*Alert, error) {
	if r == nil || r.db == nil {
		return nil, nil
	}

	if organizationID == uuid.Nil {
		return nil, nil
	}

	rows, err := r.db.Query(ctx, `
        SELECT id, organization_id, device_id, alert_type, details, created_at
        FROM lateral_movement_alerts
        WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
    `, organizationID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()

	var results []*Alert
	for rows.Next() {
		var a Alert
		var detailsBytes []byte
		if err := rows.Scan(&a.ID, &a.OrganizationID, &a.DeviceID, &a.AlertType, &detailsBytes, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		if len(detailsBytes) > 0 {
			_ = json.Unmarshal(detailsBytes, &a.Details)
		}
		results = append(results, &a)
	}

	return results, nil
}
