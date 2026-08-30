package incidentengine

import (
    "context"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

type Handler struct {
    repo *Repository
    svc  *Service
}

func NewHandler() *Handler {
    return &Handler{}
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
    if protected == nil || handler == nil || databasePool == nil {
        return
    }

    if handler.repo == nil {
        if repo, err := NewRepository(databasePool); err == nil {
            _ = repo.EnsureSchema(context.Background())
            handler.repo = repo
            handler.svc = NewService(repo)
        }
    }

    group := protected.Group("/incident-engine")
    group.GET("/health", middleware.RequirePermission(databasePool, "INCIDENT_ENGINE_VIEW"), handler.Health)
    group.POST("/ingest", middleware.RequirePermission(databasePool, "INCIDENT_ENGINE_INGEST"), handler.Ingest)
    group.POST("/train", middleware.RequirePermission(databasePool, "INCIDENT_ENGINE_TRAIN"), handler.Train)
    group.POST("/attack-story", middleware.RequirePermission(databasePool, "ATTACK_STORY_CREATE"), handler.CreateAttackStory)
}

func (h *Handler) Health(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"success": true, "status": "incident engine ready"})
}

func (h *Handler) Ingest(c *gin.Context) {
    var payload struct {
        OrganizationID string                 `json:"organization_id"`
        EventType      string                 `json:"event_type"`
        Metric         string                 `json:"metric"`
        Value          float64                `json:"value"`
        Metadata       map[string]interface{} `json:"metadata"`
    }
    if err := c.BindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid payload"})
        return
    }

    if h.svc == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "service unavailable"})
        return
    }

    orgID, err := uuid.Parse(payload.OrganizationID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid organization id"})
        return
    }

    incident, err := h.svc.IngestEvent(c.Request.Context(), orgID, payload.EventType, payload.Metric, payload.Value, payload.Metadata)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
        return
    }
    if incident == nil {
        c.JSON(http.StatusOK, gin.H{"success": true, "anomaly": false})
        return
    }

    c.JSON(http.StatusAccepted, gin.H{"success": true, "anomaly": true, "incident": incident})
}

func (h *Handler) Train(c *gin.Context) {
    var payload struct {
        OrganizationID string                   `json:"organization_id"`
        Metric         string                   `json:"metric"`
        TrainingData   []map[string]interface{} `json:"training_data"`
    }
    if err := c.BindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid payload"})
        return
    }

    if h.svc == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "service unavailable"})
        return
    }

    orgID, err := uuid.Parse(payload.OrganizationID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid organization id"})
        return
    }

    records := make([]*TrainingRecord, 0, len(payload.TrainingData))
    for _, item := range payload.TrainingData {
        value, _ := item["value"].(float64)
        isAnomaly, _ := item["is_anomaly"].(bool)
        records = append(records, &TrainingRecord{
            Value:     value,
            IsAnomaly: isAnomaly,
            Metadata:  item,
        })
    }

    model, err := h.svc.TrainModel(c.Request.Context(), orgID, payload.Metric, records)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
        return
    }

    c.JSON(http.StatusAccepted, gin.H{"success": true, "model": model})
}

func (h *Handler) CreateAttackStory(c *gin.Context) {
    var payload struct {
        OrganizationID string   `json:"organization_id"`
        IncidentIDs    []string `json:"incident_ids"`
    }
    if err := c.BindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid payload"})
        return
    }

    if h.svc == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "service unavailable"})
        return
    }

    orgID, err := uuid.Parse(payload.OrganizationID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid organization id"})
        return
    }

    incidentIDs := make([]uuid.UUID, 0, len(payload.IncidentIDs))
    for _, incidentID := range payload.IncidentIDs {
        id, err := uuid.Parse(incidentID)
        if err != nil {
            continue
        }
        incidentIDs = append(incidentIDs, id)
    }

    story, err := h.svc.CreateAttackStory(c.Request.Context(), orgID, incidentIDs)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
        return
    }

    c.JSON(http.StatusAccepted, gin.H{"success": true, "story": story})
}
