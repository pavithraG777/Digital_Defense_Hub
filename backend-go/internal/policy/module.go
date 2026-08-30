package policy

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

	group := protected.Group("/policy")
	group.POST("/evaluate", middleware.RequirePermission(databasePool, "AI_ANALYSIS_EXECUTE"), handler.EvaluatePolicy)
}

func (h *Handler) EvaluatePolicy(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "decision": "allow"})
}
