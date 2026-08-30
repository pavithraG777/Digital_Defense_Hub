package ransomware

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

	routeGroup := protected.Group("/ransomware")
	routeGroup.POST("/alerts", middleware.RequirePermission(databasePool, "THREAT_MANAGE"), handler.CreateAlert)
	routeGroup.GET("/health", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.Health)
}

func (h *Handler) CreateAlert(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "ransomware alert received"})
}

func (h *Handler) Health(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "message": "ransomware early warning healthy"})
}
