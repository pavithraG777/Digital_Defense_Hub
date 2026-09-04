package face

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

	group := protected.Group("/faces")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeFace)
	group.GET("", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.ListFaceAnalyses)
	group.GET("/:face_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetFaceAnalysis)
	handler.jobs = operational.AnalysisJobStore{DB: databasePool, Module: "FACE"}
}

func (h *Handler) AnalyzeFace(c *gin.Context) {
	h.jobs.Create(c, "FACE_MANIPULATION_ANALYSIS")
}

func (h *Handler) ListFaceAnalyses(c *gin.Context) { h.jobs.List(c) }

func (h *Handler) GetFaceAnalysis(c *gin.Context) {
	h.jobs.Get(c, c.Param("face_id"))
}
