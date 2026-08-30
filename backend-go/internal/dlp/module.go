package dlp

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

	group := protected.Group("/dlp")
	group.POST("/events", middleware.RequirePermission(databasePool, "THREAT_MANAGE"), handler.SubmitDLPEvent)
}

func (h *Handler) SubmitDLPEvent(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "DLP event accepted"})
}
