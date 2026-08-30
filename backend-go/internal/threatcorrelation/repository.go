package threatcorrelation

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

type Correlation struct {
    ID             uuid.UUID              `json:"id"`
    OrganizationID uuid.UUID              `json:"organization_id"`
    CorrelationType string                `json:"correlation_type"`
    Details        map[string]interface{} `json:"details"`
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

    q := `CREATE TABLE IF NOT EXISTS threat_correlations (
        id UUID PRIMARY KEY,
        organization_id UUID NOT NULL,
        correlation_type TEXT NOT NULL,
        details JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`

    if _, err := r.db.Exec(ctx, q); err != nil {
        return fmt.Errorf("ensure threat correlation schema: %w", err)
    }
    return nil
}

func (r *Repository) CreateCorrelation(ctx context.Context, c *Correlation) error {
    if r == nil || r.db == nil || c == nil {
        return fmt.Errorf("invalid args")
    }
    if c.ID == uuid.Nil {
        c.ID = uuid.New()
    }
    detailsBytes, _ := json.Marshal(c.Details)
    _, err := r.db.Exec(ctx, `INSERT INTO threat_correlations (id, organization_id, correlation_type, details, created_at) VALUES ($1,$2,$3,$4,$5)`, c.ID, c.OrganizationID, c.CorrelationType, detailsBytes, c.CreatedAt)
    if err != nil {
        return fmt.Errorf("create correlation: %w", err)
    }
    return nil
}

func (r *Repository) ListCorrelations(ctx context.Context, organizationID uuid.UUID, limit, offset int) ([]*Correlation, error) {
    if r == nil || r.db == nil {
        return nil, nil
    }
    if organizationID == uuid.Nil {
        return nil, nil
    }

    rows, err := r.db.Query(ctx, `SELECT id, organization_id, correlation_type, details, created_at FROM threat_correlations WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, organizationID, limit, offset)
    if err != nil {
        return nil, fmt.Errorf("list correlations: %w", err)
    }
    defer rows.Close()

    var results []*Correlation
    for rows.Next() {
        var c Correlation
        var detailsBytes []byte
        if err := rows.Scan(&c.ID, &c.OrganizationID, &c.CorrelationType, &detailsBytes, &c.CreatedAt); err != nil {
            return nil, fmt.Errorf("scan correlation: %w", err)
        }
        if len(detailsBytes) > 0 {
            _ = json.Unmarshal(detailsBytes, &c.Details)
        }
        results = append(results, &c)
    }

    return results, nil
}
