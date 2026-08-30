package persistence

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

	routeGroup := protected.Group("/persistence")
	routeGroup.GET("/checks", middleware.RequirePermission(databasePool, "PERSISTENCE_VIEW"), handler.ListChecks)
	routeGroup.POST("/discover", middleware.RequirePermission(databasePool, "PERSISTENCE_MANAGE"), handler.DiscoverPersistence)
}

func (h *Handler) ListChecks(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "checks": []any{}})
}

func (h *Handler) DiscoverPersistence(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "persistence discovery started"})
}
