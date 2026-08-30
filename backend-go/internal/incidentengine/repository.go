package incidentengine

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

type IngestionRecord struct {
    ID             uuid.UUID              `json:"id"`
    OrganizationID uuid.UUID              `json:"organization_id"`
    EventType      string                 `json:"event_type"`
    Metric         string                 `json:"metric"`
    Value          float64                `json:"value"`
    Metadata       map[string]interface{} `json:"metadata"`
    CreatedAt      time.Time              `json:"created_at"`
}

type TrainingRecord struct {
    ID             uuid.UUID              `json:"id"`
    OrganizationID uuid.UUID              `json:"organization_id"`
    Metric         string                 `json:"metric"`
    Value          float64                `json:"value"`
    IsAnomaly      bool                   `json:"is_anomaly"`
    Metadata       map[string]interface{} `json:"metadata"`
    CreatedAt      time.Time              `json:"created_at"`
}

type Model struct {
    OrganizationID uuid.UUID `json:"organization_id"`
    Metric         string    `json:"metric"`
    Threshold      float64   `json:"threshold"`
    UpdatedAt      time.Time `json:"updated_at"`
}

type Incident struct {
    ID             uuid.UUID              `json:"id"`
    OrganizationID uuid.UUID              `json:"organization_id"`
    Title          string                 `json:"title"`
    Description    string                 `json:"description"`
    SourceEvent    map[string]interface{} `json:"source_event"`
    CreatedAt      time.Time              `json:"created_at"`
}

type Story struct {
    ID             uuid.UUID                `json:"id"`
    OrganizationID uuid.UUID                `json:"organization_id"`
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

    q := `CREATE TABLE IF NOT EXISTS incident_engine_records (
        id UUID PRIMARY KEY,
        organization_id UUID NOT NULL,
        event_type TEXT NOT NULL,
        metric TEXT NOT NULL,
        value DOUBLE PRECISION NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS incident_engine_training (
        id UUID PRIMARY KEY,
        organization_id UUID NOT NULL,
        metric TEXT NOT NULL,
        value DOUBLE PRECISION NOT NULL,
        is_anomaly BOOLEAN NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS incident_engine_models (
        organization_id UUID NOT NULL,
        metric TEXT NOT NULL,
        threshold DOUBLE PRECISION NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (organization_id, metric)
    );

    CREATE TABLE IF NOT EXISTS incident_engine_incidents (
        id UUID PRIMARY KEY,
        organization_id UUID NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        source_event JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS incident_engine_stories (
        id UUID PRIMARY KEY,
        organization_id UUID NOT NULL,
        title TEXT NOT NULL,
        timeline JSONB NOT NULL DEFAULT '[]',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );`

    if _, err := r.db.Exec(ctx, q); err != nil {
        return fmt.Errorf("ensure incident engine schema: %w", err)
    }
    return nil
}

func (r *Repository) SaveIngestionRecord(ctx context.Context, record *IngestionRecord) error {
    if r == nil || r.db == nil || record == nil {
        return fmt.Errorf("invalid args")
    }
    if record.ID == uuid.Nil {
        record.ID = uuid.New()
    }
    metadataBytes, _ := json.Marshal(record.Metadata)
    _, err := r.db.Exec(ctx, `INSERT INTO incident_engine_records (id, organization_id, event_type, metric, value, metadata, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, record.ID, record.OrganizationID, record.EventType, record.Metric, record.Value, metadataBytes, record.CreatedAt)
    if err != nil {
        return fmt.Errorf("save ingestion record: %w", err)
    }
    return nil
}

func (r *Repository) SaveTrainingRecord(ctx context.Context, record *TrainingRecord) error {
    if r == nil || r.db == nil || record == nil {
        return fmt.Errorf("invalid args")
    }
    if record.ID == uuid.Nil {
        record.ID = uuid.New()
    }
    metadataBytes, _ := json.Marshal(record.Metadata)
    _, err := r.db.Exec(ctx, `INSERT INTO incident_engine_training (id, organization_id, metric, value, is_anomaly, metadata, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, record.ID, record.OrganizationID, record.Metric, record.Value, record.IsAnomaly, metadataBytes, record.CreatedAt)
    if err != nil {
        return fmt.Errorf("save training record: %w", err)
    }
    return nil
}

func (r *Repository) SaveModel(ctx context.Context, model *Model) error {
    if r == nil || r.db == nil || model == nil {
        return fmt.Errorf("invalid args")
    }
    _, err := r.db.Exec(ctx, `INSERT INTO incident_engine_models (organization_id, metric, threshold, updated_at) VALUES ($1,$2,$3,$4) ON CONFLICT (organization_id, metric) DO UPDATE SET threshold = EXCLUDED.threshold, updated_at = EXCLUDED.updated_at`, model.OrganizationID, model.Metric, model.Threshold, model.UpdatedAt)
    if err != nil {
        return fmt.Errorf("save model: %w", err)
    }
    return nil
}

func (r *Repository) GetModel(ctx context.Context, organizationID uuid.UUID, metric string) (*Model, error) {
    if r == nil || r.db == nil {
        return nil, fmt.Errorf("repository unavailable")
    }
    if organizationID == uuid.Nil || metric == "" {
        return nil, fmt.Errorf("invalid args")
    }

    var model Model
    err := r.db.QueryRow(ctx, `SELECT organization_id, metric, threshold, updated_at FROM incident_engine_models WHERE organization_id = $1 AND metric = $2`, organizationID, metric).Scan(&model.OrganizationID, &model.Metric, &model.Threshold, &model.UpdatedAt)
    if err != nil {
        return nil, err
    }
    return &model, nil
}

func (r *Repository) CreateIncident(ctx context.Context, incident *Incident) error {
    if r == nil || r.db == nil || incident == nil {
        return fmt.Errorf("invalid args")
    }
    if incident.ID == uuid.Nil {
        incident.ID = uuid.New()
    }
    eventBytes, _ := json.Marshal(incident.SourceEvent)
    _, err := r.db.Exec(ctx, `INSERT INTO incident_engine_incidents (id, organization_id, title, description, source_event, created_at) VALUES ($1,$2,$3,$4,$5,$6)`, incident.ID, incident.OrganizationID, incident.Title, incident.Description, eventBytes, incident.CreatedAt)
    if err != nil {
        return fmt.Errorf("create incident: %w", err)
    }
    return nil
}

func (r *Repository) GetIncidentByID(ctx context.Context, id uuid.UUID) (*Incident, error) {
    if r == nil || r.db == nil {
        return nil, fmt.Errorf("repository unavailable")
    }
    if id == uuid.Nil {
        return nil, fmt.Errorf("invalid incident id")
    }

    var incident Incident
    var eventBytes []byte
    err := r.db.QueryRow(ctx, `SELECT id, organization_id, title, description, source_event, created_at FROM incident_engine_incidents WHERE id = $1`, id).Scan(&incident.ID, &incident.OrganizationID, &incident.Title, &incident.Description, &eventBytes, &incident.CreatedAt)
    if err != nil {
        return nil, err
    }
    if len(eventBytes) > 0 {
        _ = json.Unmarshal(eventBytes, &incident.SourceEvent)
    }
    return &incident, nil
}

func (r *Repository) ListIncidents(ctx context.Context, organizationID uuid.UUID, limit, offset int) ([]*Incident, error) {
    if r == nil || r.db == nil {
        return nil, nil
    }
    if organizationID == uuid.Nil {
        return nil, nil
    }

    rows, err := r.db.Query(ctx, `SELECT id, organization_id, title, description, source_event, created_at FROM incident_engine_incidents WHERE organization_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, organizationID, limit, offset)
    if err != nil {
        return nil, fmt.Errorf("list incidents: %w", err)
    }
    defer rows.Close()

    var results []*Incident
    for rows.Next() {
        var incident Incident
        var eventBytes []byte
        if err := rows.Scan(&incident.ID, &incident.OrganizationID, &incident.Title, &incident.Description, &eventBytes, &incident.CreatedAt); err != nil {
            return nil, fmt.Errorf("scan incident: %w", err)
        }
        if len(eventBytes) > 0 {
            _ = json.Unmarshal(eventBytes, &incident.SourceEvent)
        }
        results = append(results, &incident)
    }

    return results, nil
}

func (r *Repository) SaveStory(ctx context.Context, story *Story) error {
    if r == nil || r.db == nil || story == nil {
        return fmt.Errorf("invalid args")
    }
    if story.ID == uuid.Nil {
        story.ID = uuid.New()
    }
    timelineBytes, _ := json.Marshal(story.Timeline)
    _, err := r.db.Exec(ctx, `INSERT INTO incident_engine_stories (id, organization_id, title, timeline, created_at) VALUES ($1,$2,$3,$4,$5)`, story.ID, story.OrganizationID, story.Title, timelineBytes, story.CreatedAt)
    if err != nil {
        return fmt.Errorf("save story: %w", err)
    }
    return nil
}

func (r *Repository) RecentRecordsByMetric(ctx context.Context, organizationID uuid.UUID, metric string, limit int) ([]*IngestionRecord, error) {
    if r == nil || r.db == nil {
        return nil, nil
    }
    if organizationID == uuid.Nil || metric == "" {
        return nil, nil
    }

    rows, err := r.db.Query(ctx, `SELECT id, organization_id, event_type, metric, value, metadata, created_at FROM incident_engine_records WHERE organization_id = $1 AND metric = $2 ORDER BY created_at DESC LIMIT $3`, organizationID, metric, limit)
    if err != nil {
        return nil, fmt.Errorf("recent records: %w", err)
    }
    defer rows.Close()

    var results []*IngestionRecord
    for rows.Next() {
        var rec IngestionRecord
        var metaBytes []byte
        if err := rows.Scan(&rec.ID, &rec.OrganizationID, &rec.EventType, &rec.Metric, &rec.Value, &metaBytes, &rec.CreatedAt); err != nil {
            return nil, fmt.Errorf("scan ingestion record: %w", err)
        }
        if len(metaBytes) > 0 {
            _ = json.Unmarshal(metaBytes, &rec.Metadata)
        }
        results = append(results, &rec)
    }

    return results, nil
}
