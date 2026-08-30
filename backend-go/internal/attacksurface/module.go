package attacksurface

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

	group := protected.Group("/attack-surface")
	group.GET("", middleware.RequirePermission(databasePool, "ATTACK_SURFACE_VIEW"), handler.ListSurface)
	group.GET("/:id", middleware.RequirePermission(databasePool, "ATTACK_SURFACE_VIEW"), handler.GetSurface)
	group.POST("/assess", middleware.RequirePermission(databasePool, "ATTACK_SURFACE_ASSESS"), handler.AssessSurface)
}

func (h *Handler) ListSurface(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []any{}})
}

func (h *Handler) GetSurface(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"id": c.Param("id")}})
}

func (h *Handler) AssessSurface(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "attack surface assessment started"})
}
