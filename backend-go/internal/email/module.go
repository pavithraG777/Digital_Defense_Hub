package email

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

	group := protected.Group("/emails")
	group.POST("/analyze", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.AnalyzeEmail)
	group.GET("", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.ListEmailAnalyses)
	group.GET("/:email_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetEmailAnalysis)
	handler.jobs = operational.AnalysisJobStore{DB: databasePool, Module: "EMAIL"}
}

func (h *Handler) AnalyzeEmail(c *gin.Context) {
	h.jobs.Create(c, "EMAIL_SECURITY_ANALYSIS")
}

func (h *Handler) ListEmailAnalyses(c *gin.Context) { h.jobs.List(c) }

func (h *Handler) GetEmailAnalysis(c *gin.Context) {
	h.jobs.Get(c, c.Param("email_id"))
}
