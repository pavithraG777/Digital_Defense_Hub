package incidentanalytics

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}

	group := protected.Group("/incident-analytics")
	group.GET("", middleware.RequirePermission(databasePool, "INCIDENT_ANALYTICS_VIEW"), handler.ListAnalytics)
	group.GET(":id", middleware.RequirePermission(databasePool, "INCIDENT_ANALYTICS_VIEW"), handler.GetAnalytics)
	group.POST("/generate", middleware.RequirePermission(databasePool, "INCIDENT_ANALYTICS_GENERATE"), handler.GenerateAnalytics)
	group.POST("/archive", middleware.RequirePermission(databasePool, "INCIDENT_ANALYTICS_ARCHIVE"), handler.ArchiveAnalytics)
}

func (h *Handler) ListAnalytics(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []any{}})
}

func (h *Handler) GetAnalytics(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"id": c.Param("id")}})
}

func (h *Handler) GenerateAnalytics(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "incident analytics generation started"})
}

func (h *Handler) ArchiveAnalytics(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "incident analytics archived"})
}
