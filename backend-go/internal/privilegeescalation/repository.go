package privilegeescalation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Detection struct {
	ID             uuid.UUID              `json:"id"`
	OrganizationID uuid.UUID              `json:"organization_id"`
	Host           string                 `json:"host"`
	UserID         uuid.UUID              `json:"user_id"`
	DetectionType  string                 `json:"detection_type"`
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
		`CREATE TABLE IF NOT EXISTS privilege_escalation_detections (
            id UUID PRIMARY KEY,
            organization_id UUID NOT NULL,
            host TEXT NOT NULL,
            user_id UUID NOT NULL,
            detection_type TEXT NOT NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
			status TEXT NOT NULL DEFAULT 'OPEN',
			review_note TEXT,
			reviewed_by UUID,
			reviewed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );`,
		`ALTER TABLE privilege_escalation_detections ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'OPEN'`,
		`ALTER TABLE privilege_escalation_detections ADD COLUMN IF NOT EXISTS review_note TEXT`,
		`ALTER TABLE privilege_escalation_detections ADD COLUMN IF NOT EXISTS reviewed_by UUID`,
		`ALTER TABLE privilege_escalation_detections ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ`,
	}

	for _, q := range queries {
		if _, err := r.db.Exec(ctx, q); err != nil {
			return fmt.Errorf("ensure privilege escalation schema: %w", err)
		}
	}
	return nil
}

func (r *Repository) CreateDetection(ctx context.Context, d *Detection) (*Detection, error) {
	if r == nil || r.db == nil || d == nil {
		return nil, fmt.Errorf("invalid create detection input")
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}

	metaBytes, _ := json.Marshal(d.Metadata)

	_, err := r.db.Exec(ctx, `
        INSERT INTO privilege_escalation_detections (id, organization_id, host, user_id, detection_type, metadata, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
    `, d.ID, d.OrganizationID, d.Host, d.UserID, d.DetectionType, metaBytes, d.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create detection: %w", err)
	}
	return d, nil
}

func (r *Repository) ListDetections(ctx context.Context, organizationID uuid.UUID, limit, offset int) ([]*Detection, error) {
	if r == nil || r.db == nil {
		return nil, nil
	}
	if organizationID == uuid.Nil {
		return nil, nil
	}

	rows, err := r.db.Query(ctx, `
        SELECT id, organization_id, host, user_id, detection_type, metadata, created_at
        FROM privilege_escalation_detections
        WHERE organization_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
    `, organizationID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list detections: %w", err)
	}
	defer rows.Close()

	var results []*Detection
	for rows.Next() {
		var d Detection
		var metaBytes []byte
		if err := rows.Scan(&d.ID, &d.OrganizationID, &d.Host, &d.UserID, &d.DetectionType, &metaBytes, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan detection: %w", err)
		}
		if len(metaBytes) > 0 {
			_ = json.Unmarshal(metaBytes, &d.Metadata)
		}
		results = append(results, &d)
	}
	return results, nil
}
