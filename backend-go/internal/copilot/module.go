package copilot

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

	routeGroup := protected.Group("/copilot")
	routeGroup.GET("/assist", middleware.RequirePermission(databasePool, "COPILOT_USE"), handler.Assist)
	routeGroup.POST("/summarize", middleware.RequirePermission(databasePool, "COPILOT_USE"), handler.Summarize)
	routeGroup.GET("/:id", middleware.RequirePermission(databasePool, "COPILOT_USE"), handler.GetJob)
	handler.jobs = operational.AnalysisJobStore{DB: databasePool, Module: "SECURITY_COPILOT"}
}

func (h *Handler) Assist(c *gin.Context) {
	h.jobs.List(c)
}

func (h *Handler) Summarize(c *gin.Context) {
	h.jobs.Create(c, "INCIDENT_SUMMARY")
}

func (h *Handler) GetJob(c *gin.Context) { h.jobs.Get(c, c.Param("id")) }
