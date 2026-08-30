package integration

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

	routeGroup := protected.Group("/integration")
	routeGroup.POST("/siem", middleware.RequirePermission(databasePool, "INTEGRATION_MANAGE"), handler.SendToSIEM)
	routeGroup.POST("/ticket", middleware.RequirePermission(databasePool, "INTEGRATION_MANAGE"), handler.CreateTicket)
}

func (h *Handler) SendToSIEM(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "message": "SIEM integration event sent"})
}

func (h *Handler) CreateTicket(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "message": "incident ticket created"})
}
