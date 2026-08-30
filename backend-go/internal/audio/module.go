package audio

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

	group := protected.Group("/audio")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeAudio)
	group.GET("/:audio_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetAudioAnalysis)
}

func (h *Handler) AnalyzeAudio(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "audio analysis queued"})
}

func (h *Handler) GetAudioAnalysis(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"audio_id": c.Param("audio_id")}})
}
