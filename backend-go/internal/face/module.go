package face

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

	group := protected.Group("/faces")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeFace)
	group.GET("/:face_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetFaceAnalysis)
}

func (h *Handler) AnalyzeFace(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "face analysis queued"})
}

func (h *Handler) GetFaceAnalysis(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"face_id": c.Param("face_id")}})
}
