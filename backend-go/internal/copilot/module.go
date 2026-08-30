package copilot

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

	routeGroup := protected.Group("/copilot")
	routeGroup.GET("/assist", middleware.RequirePermission(databasePool, "COPILOT_USE"), handler.Assist)
	routeGroup.POST("/summarize", middleware.RequirePermission(databasePool, "COPILOT_USE"), handler.Summarize)
}

func (h *Handler) Assist(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "message": "security copilot assistance delivered"})
}

func (h *Handler) Summarize(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "message": "incident summary generated"})
}
