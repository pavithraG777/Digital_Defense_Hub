package incidentengine

import (
    "context"
    "fmt"
    "math"
    "sort"
    "time"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
)

type Service struct {
    repo *Repository
}

func NewService(r *Repository) *Service {
    return &Service{repo: r}
}

func (s *Service) IngestEvent(ctx context.Context, orgID uuid.UUID, eventType, metric string, value float64, metadata map[string]interface{}) (*Incident, error) {
    if s == nil {
        return nil, fmt.Errorf("service unavailable")
    }
    if orgID == uuid.Nil || metric == "" || eventType == "" {
        return nil, fmt.Errorf("invalid ingest payload")
    }

    record := &IngestionRecord{
        OrganizationID: orgID,
        EventType:      eventType,
        Metric:         metric,
        Value:          value,
        Metadata:       metadata,
        CreatedAt:      time.Now().UTC(),
    }
    if s.repo != nil {
        if err := s.repo.SaveIngestionRecord(ctx, record); err != nil {
            return nil, err
        }
    }

    model, err := s.repo.GetModel(ctx, orgID, metric)
    if err != nil && err != pgx.ErrNoRows {
        return nil, err
    }

    if model == nil {
        model = &Model{OrganizationID: orgID, Metric: metric, Threshold: 100.0, UpdatedAt: time.Now().UTC()}
    }

    rawAnomaly := value > model.Threshold
    if rawAnomaly {
        incident := &Incident{
            OrganizationID: orgID,
            Title:          fmt.Sprintf("Anomaly detected for %s", metric),
            Description:    fmt.Sprintf("Detected %s value %.2f above threshold %.2f", metric, value, model.Threshold),
            SourceEvent: map[string]interface{}{
                "event_type": eventType,
                "metric":     metric,
                "value":      value,
                "metadata":   metadata,
            },
            CreatedAt: time.Now().UTC(),
        }
        if s.repo != nil {
            if err := s.repo.CreateIncident(ctx, incident); err != nil {
                return nil, err
            }
        }
        return incident, nil
    }

    return nil, nil
}

func (s *Service) TrainModel(ctx context.Context, orgID uuid.UUID, metric string, records []*TrainingRecord) (*Model, error) {
    if s == nil {
        return nil, fmt.Errorf("service unavailable")
    }
    if orgID == uuid.Nil || metric == "" {
        return nil, fmt.Errorf("invalid train payload")
    }
    if len(records) == 0 {
        return nil, fmt.Errorf("no training records")
    }

    for _, rec := range records {
        rec.OrganizationID = orgID
        rec.Metric = metric
        rec.CreatedAt = time.Now().UTC()
        if err := s.repo.SaveTrainingRecord(ctx, rec); err != nil {
            return nil, err
        }
    }

    thresholds := make([]float64, 0, len(records))
    for _, rec := range records {
        thresholds = append(thresholds, rec.Value)
    }
    sort.Float64s(thresholds)

    index := int(math.Max(0, float64(len(thresholds)-2)))
    threshold := thresholds[index]
    model := &Model{OrganizationID: orgID, Metric: metric, Threshold: threshold, UpdatedAt: time.Now().UTC()}

    if err := s.repo.SaveModel(ctx, model); err != nil {
        return nil, err
    }

    return model, nil
}

func (s *Service) BuildTrainingRecordsFromRecent(ctx context.Context, orgID uuid.UUID, metric string, limit int) ([]*TrainingRecord, error) {
    if s == nil {
        return nil, fmt.Errorf("service unavailable")
    }
    if orgID == uuid.Nil || metric == "" {
        return nil, fmt.Errorf("invalid args")
    }

    records, err := s.repo.RecentRecordsByMetric(ctx, orgID, metric, limit)
    if err != nil {
        return nil, err
    }

    trainingRecords := make([]*TrainingRecord, 0, len(records))
    for _, rec := range records {
        trainingRecords = append(trainingRecords, &TrainingRecord{
            OrganizationID: rec.OrganizationID,
            Metric:         rec.Metric,
            Value:          rec.Value,
            IsAnomaly:      rec.Value > 0,
            Metadata:       rec.Metadata,
            CreatedAt:      rec.CreatedAt,
        })
    }

    return trainingRecords, nil
}

func (s *Service) CreateAttackStory(ctx context.Context, orgID uuid.UUID, incidentIDs []uuid.UUID) (*Story, error) {
    if s == nil {
        return nil, fmt.Errorf("service unavailable")
    }
    if orgID == uuid.Nil {
        return nil, fmt.Errorf("invalid org id")
    }
    if len(incidentIDs) == 0 {
        return nil, fmt.Errorf("no incidents provided")
    }

    timeline := make([]map[string]interface{}, 0, len(incidentIDs))
    for _, incidentID := range incidentIDs {
        incident, err := s.repo.GetIncidentByID(ctx, incidentID)
        if err != nil {
            return nil, err
        }
        if incident.OrganizationID != orgID {
            continue
        }
        timeline = append(timeline, map[string]interface{}{
            "incident_id":  incident.ID.String(),
            "title":        incident.Title,
            "description":  incident.Description,
            "created_at":   incident.CreatedAt,
            "source_event": incident.SourceEvent,
        })
    }

    if len(timeline) == 0 {
        return nil, fmt.Errorf("no matching incidents found")
    }

    story := &Story{
        OrganizationID: orgID,
        Title:          "Incident Attack Story",
        Timeline:       timeline,
        CreatedAt:      time.Now().UTC(),
    }
    if err := s.repo.SaveStory(ctx, story); err != nil {
        return nil, err
    }

    return story, nil
}
