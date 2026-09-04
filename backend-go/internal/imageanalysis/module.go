package imageanalysis

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

	group := protected.Group("/images")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeImage)
	group.GET("", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.ListImageAnalyses)
	group.GET("/:image_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetImageAnalysis)
	handler.jobs = operational.AnalysisJobStore{DB: databasePool, Module: "IMAGE"}
}

func (h *Handler) AnalyzeImage(c *gin.Context) {
	h.jobs.Create(c, "IMAGE_FORENSICS")
}

func (h *Handler) ListImageAnalyses(c *gin.Context) { h.jobs.List(c) }

func (h *Handler) GetImageAnalysis(c *gin.Context) {
	h.jobs.Get(c, c.Param("image_id"))
}
