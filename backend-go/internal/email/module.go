package email

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

	group := protected.Group("/emails")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeEmail)
	group.GET("/:email_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetEmailAnalysis)
}

func (h *Handler) AnalyzeEmail(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "email analysis queued"})
}

func (h *Handler) GetEmailAnalysis(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"email_id": c.Param("email_id")}})
}
