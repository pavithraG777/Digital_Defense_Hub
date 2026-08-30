package baseline

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

type Handler struct{
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

	// wire repository and service
	if handler.repo == nil {
		if repo, err := NewRepository(databasePool); err == nil {
			_ = repo.EnsureSchema(context.Background())
			handler.repo = repo
			handler.svc = NewService(repo)
		}
	}

	group := protected.Group("/baseline")
	group.GET("/status", middleware.RequirePermission(databasePool, "BASELINE_VIEW"), handler.Status)
	group.GET("/anomalies", middleware.RequirePermission(databasePool, "BASELINE_VIEW"), handler.Anomalies)
	group.POST("/analyze", middleware.RequirePermission(databasePool, "BASELINE_CREATE"), handler.Analyze)
}

func (h *Handler) Status(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "status": "baseline healthy"})
}

func (h *Handler) Anomalies(c *gin.Context) {
	// pagination and optional org
	orgStr := c.Query("org_id")
	page := c.DefaultQuery("page", "1")
	if orgStr != "" && h.repo != nil {
		if orgID, err := uuid.Parse(orgStr); err == nil {
			results, err := h.repo.ListAnomalies(c.Request.Context(), orgID, 50, 0)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"success": true, "anomalies": results, "page": page})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "anomalies": []any{}, "page": page})
}

func (h *Handler) Analyze(c *gin.Context) {
	var payload struct{
		OrganizationID string                 `json:"organization_id"`
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

	detected, err := h.svc.AnalyzeMetric(c.Request.Context(), orgID, payload.Metric, payload.Value, payload.Metadata)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	if detected {
		c.JSON(http.StatusAccepted, gin.H{"success": true, "anomaly": true})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "anomaly": false})
}
