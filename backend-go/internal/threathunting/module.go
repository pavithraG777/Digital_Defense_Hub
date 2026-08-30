package threathunting

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

	group := protected.Group("/threat-hunting")
	group.GET("", middleware.RequirePermission(databasePool, "THREAT_HUNTING_VIEW"), handler.ListHunts)
	group.GET("/:id", middleware.RequirePermission(databasePool, "THREAT_HUNTING_VIEW"), handler.GetHunt)
	group.POST("/search", middleware.RequirePermission(databasePool, "THREAT_HUNTING_SEARCH"), handler.SearchAlerts)
	group.POST("/investigate", middleware.RequirePermission(databasePool, "THREAT_HUNTING_INVESTIGATE"), handler.Investigate)
}

func (h *Handler) ListHunts(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []any{}})
}

func (h *Handler) GetHunt(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"id": c.Param("id")}})
}

func (h *Handler) SearchAlerts(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "threat hunting search initiated"})
}

func (h *Handler) Investigate(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "investigation started"})
}
