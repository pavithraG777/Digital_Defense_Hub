package surveillance

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

	group := protected.Group("/surveillance")
	group.POST("/track", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.TrackSurveillance)
	group.GET("/insights", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.ListInsights)
	group.GET("/insights/:id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetInsight)
	handler.jobs = operational.AnalysisJobStore{DB: databasePool, Module: "SURVEILLANCE"}
}

func (h *Handler) TrackSurveillance(c *gin.Context) {
	h.jobs.Create(c, "SURVEILLANCE_ANALYSIS")
}

func (h *Handler) ListInsights(c *gin.Context) {
	h.jobs.List(c)
}

func (h *Handler) GetInsight(c *gin.Context) { h.jobs.Get(c, c.Param("id")) }
