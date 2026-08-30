package dfir

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}

	dfirGroup := protected.Group("/dfir")
	dfirGroup.GET("/health", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.Health)
	dfirGroup.POST("/assess", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.Assess)
	dfirGroup.POST("/ml/score", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.ProxyML)
	dfirGroup.POST("/feature/score", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.ExtractAndScore)
	dfirGroup.POST("/incidents", middleware.RequirePermission(databasePool, "THREAT_MANAGE"), handler.CreateIncident)
	dfirGroup.GET("/incidents", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.ListIncidents)
	dfirGroup.GET("/incidents/:id", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.GetIncident)
	dfirGroup.GET("/incidents/:id/evidence", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.ListIncidentEvidence)
	dfirGroup.GET("/incidents/:id/timeline", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.ListIncidentTimeline)
	dfirGroup.POST("/ingest", middleware.RequirePermission(databasePool, "THREAT_MANAGE"), handler.EnqueueEvent)
}
