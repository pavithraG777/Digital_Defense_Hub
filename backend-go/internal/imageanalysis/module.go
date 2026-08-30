package imageanalysis

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

	group := protected.Group("/images")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeImage)
	group.GET("/:image_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetImageAnalysis)
}

func (h *Handler) AnalyzeImage(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "image analysis queued"})
}

func (h *Handler) GetImageAnalysis(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"image_id": c.Param("image_id")}})
}
