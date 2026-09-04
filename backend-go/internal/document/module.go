package document

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

	group := protected.Group("/documents")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeDocument)
	group.GET("", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.ListDocuments)
	group.GET("/:document_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetDocument)
	handler.jobs = operational.AnalysisJobStore{DB: databasePool, Module: "DOCUMENT"}
}

func (h *Handler) AnalyzeDocument(c *gin.Context) {
	h.jobs.Create(c, "OCR_EXTRACTION")
}

func (h *Handler) ListDocuments(c *gin.Context) { h.jobs.List(c) }

func (h *Handler) GetDocument(c *gin.Context) {
	h.jobs.Get(c, c.Param("document_id"))
}
