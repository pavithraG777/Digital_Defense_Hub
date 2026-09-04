package audio

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct{ jobs operational.AnalysisJobStore }

func NewHandler() *Handler {
	return &Handler{}
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}

	group := protected.Group("/audio")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeAudio)
	group.GET("", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.ListAudioAnalyses)
	group.GET("/:audio_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetAudioAnalysis)
	handler.jobs = operational.AnalysisJobStore{DB: databasePool, Module: "AUDIO"}
}

func (h *Handler) AnalyzeAudio(c *gin.Context) {
	h.jobs.Create(c, "AUDIO_FORENSICS")
}

func (h *Handler) ListAudioAnalyses(c *gin.Context) { h.jobs.List(c) }

func (h *Handler) GetAudioAnalysis(c *gin.Context) {
	h.jobs.Get(c, c.Param("audio_id"))
}
