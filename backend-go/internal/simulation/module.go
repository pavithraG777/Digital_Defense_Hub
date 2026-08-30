package simulation

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

	routeGroup := protected.Group("/simulation")
	routeGroup.POST("/run", middleware.RequirePermission(databasePool, "SIMULATION_RUN"), handler.Run)
	routeGroup.GET("/status", middleware.RequirePermission(databasePool, "SIMULATION_VIEW"), handler.Status)
}

func (h *Handler) Run(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "threat simulation started"})
}

func (h *Handler) Status(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "status": "idle"})
}
