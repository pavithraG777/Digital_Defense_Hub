package baseline

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

type Anomaly struct {
    ID             uuid.UUID              `json:"id"`
    OrganizationID uuid.UUID              `json:"organization_id"`
    Metric         string                 `json:"metric"`
    Value          float64                `json:"value"`
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

    q := `CREATE TABLE IF NOT EXISTS baseline_anomalies (
        id UUID PRIMARY KEY,
        organization_id UUID NOT NULL,
        metric TEXT NOT NULL,
        value DOUBLE PRECISION NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`

    if _, err := r.db.Exec(ctx, q); err != nil {
        return fmt.Errorf("ensure baseline schema: %w", err)
    }

    return nil
}

func (r *Repository) CreateAnomaly(ctx context.Context, a *Anomaly) error {
    if r == nil || r.db == nil || a == nil {
        return fmt.Errorf("invalid args")
    }
    if a.ID == uuid.Nil {
        a.ID = uuid.New()
    }

    metadataBytes, _ := json.Marshal(a.Metadata)

    _, err := r.db.Exec(ctx, `INSERT INTO baseline_anomalies (id, organization_id, metric, value, metadata, created_at) VALUES ($1,$2,$3,$4,$5,$6)`, a.ID, a.OrganizationID, a.Metric, a.Value, metadataBytes, a.CreatedAt)
    if err != nil {
        return fmt.Errorf("create anomaly: %w", err)
    }
    return nil
}

func (r *Repository) ListAnomalies(ctx context.Context, organizationID uuid.UUID, limit, offset int) ([]*Anomaly, error) {
    if r == nil || r.db == nil {
        return nil, nil
    }
    if organizationID == uuid.Nil {
        return nil, nil
    }

    rows, err := r.db.Query(ctx, `SELECT id, organization_id, metric, value, metadata, created_at FROM baseline_anomalies WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, organizationID, limit, offset)
    if err != nil {
        return nil, fmt.Errorf("list anomalies: %w", err)
    }
    defer rows.Close()

    var results []*Anomaly
    for rows.Next() {
        var a Anomaly
        var metaBytes []byte
        if err := rows.Scan(&a.ID, &a.OrganizationID, &a.Metric, &a.Value, &metaBytes, &a.CreatedAt); err != nil {
            return nil, fmt.Errorf("scan anomaly: %w", err)
        }
        if len(metaBytes) > 0 {
            _ = json.Unmarshal(metaBytes, &a.Metadata)
        }
        results = append(results, &a)
    }

    return results, nil
}
