package threatcorrelation

import (
    "context"
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/google/uuid"
    "github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

type Handler struct{
    repo *Repository
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
        }
    }

    group := protected.Group("/threatcorrelation")
    group.GET("/list", middleware.RequirePermission(databasePool, "THREAT_CORRELATION_VIEW"), handler.List)
    group.POST("/create", middleware.RequirePermission(databasePool, "THREAT_CORRELATION_CREATE"), handler.Create)
}

func (h *Handler) List(c *gin.Context) {
    orgStr := c.Query("org_id")
    page := c.DefaultQuery("page", "1")
    limit := 50
    offset := 0

    if orgStr != "" && h.repo != nil {
        if orgID, err := uuid.Parse(orgStr); err == nil {
            results, err := h.repo.ListCorrelations(c.Request.Context(), orgID, limit, offset)
            if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
                return
            }
            c.JSON(http.StatusOK, gin.H{"success": true, "correlations": results, "page": page})
            return
        }
    }

    c.JSON(http.StatusOK, gin.H{"success": true, "correlations": []any{}, "page": page})
}

func (h *Handler) Create(c *gin.Context) {
    var payload struct{
        OrganizationID string                 `json:"organization_id"`
        CorrelationType string               `json:"correlation_type"`
        Details map[string]interface{}       `json:"details"`
    }
    if err := c.BindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid payload"})
        return
    }

    if h.repo == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "repository unavailable"})
        return
    }

    orgID, err := uuid.Parse(payload.OrganizationID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid organization id"})
        return
    }

    corr := &Correlation{
        OrganizationID: orgID,
        CorrelationType: payload.CorrelationType,
        Details: payload.Details,
        CreatedAt: time.Now(),
    }
    if err := h.repo.CreateCorrelation(c.Request.Context(), corr); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
        return
    }

    c.JSON(http.StatusAccepted, gin.H{"success": true, "id": corr.ID})
}
