package risk

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

	riskGroup := protected.Group("/risk")
	riskGroup.POST("/incidents/:incident_id/calculate", middleware.RequirePermission(databasePool, "AI_ANALYSIS_EXECUTE"), handler.CalculateIncidentRisk)
	riskGroup.GET("/entities/:entity_id", middleware.RequirePermission(databasePool, "AI_ANALYSIS_VIEW"), handler.GetEntityRisk)
}

func (h *Handler) CalculateIncidentRisk(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "message": "risk calculated"})
}

func (h *Handler) GetEntityRisk(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"entity_id": c.Param("entity_id")}})
}
