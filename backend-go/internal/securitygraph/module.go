package securitygraph

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

const (
	securityGraphRoute           = "/security-graph"
	permissionViewSecurityGraph  = "THREAT_VIEW"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Health(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "message": "security graph healthy"})
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}

	group := protected.Group(securityGraphRoute)
	group.GET("/health", middleware.RequirePermission(databasePool, permissionViewSecurityGraph), handler.Health)
}
