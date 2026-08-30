package behavior

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

	group := protected.Group("/behavior")
	group.POST("/events", middleware.RequirePermission(databasePool, "THREAT_MANAGE"), handler.SubmitBehaviorEvent)
	group.GET("/baselines/:user_id", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.GetBaseline)
}

func (h *Handler) SubmitBehaviorEvent(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "behavior event accepted"})
}

func (h *Handler) GetBaseline(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"user_id": c.Param("user_id")}})
}
