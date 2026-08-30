package surveillance

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

	group := protected.Group("/surveillance")
	group.POST("/track", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.TrackSurveillance)
	group.GET("/insights", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.ListInsights)
}

func (h *Handler) TrackSurveillance(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "surveillance intelligence queued"})
}

func (h *Handler) ListInsights(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []any{}})
}
