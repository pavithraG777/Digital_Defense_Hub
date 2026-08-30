package document

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

	group := protected.Group("/documents")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeDocument)
	group.GET("/:document_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetDocument)
}

func (h *Handler) AnalyzeDocument(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "document analysis queued"})
}

func (h *Handler) GetDocument(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"document_id": c.Param("document_id")}})
}
