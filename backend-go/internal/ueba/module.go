package ueba

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

	routeGroup := protected.Group("/ueba")
	routeGroup.POST("/events", middleware.RequirePermission(databasePool, "THREAT_MANAGE"), handler.SubmitEvent)
	routeGroup.GET("/anomalies", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.ListAnomalies)
}

func (h *Handler) SubmitEvent(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "UEBA event received"})
}

func (h *Handler) ListAnomalies(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []any{}})
}
