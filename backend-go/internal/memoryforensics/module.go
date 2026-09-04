package memoryforensics

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

	routeGroup := protected.Group("/memoryforensics")
	routeGroup.POST("/scan", middleware.RequirePermission(databasePool, "MEMORY_FORENSICS_MANAGE"), handler.ScanMemory)
	routeGroup.GET("/reports", middleware.RequirePermission(databasePool, "MEMORY_FORENSICS_VIEW"), handler.ListReports)
	routeGroup.GET("/reports/:id", middleware.RequirePermission(databasePool, "MEMORY_FORENSICS_VIEW"), handler.GetReport)
	handler.jobs = operational.AnalysisJobStore{DB: databasePool, Module: "MEMORY_FORENSICS"}
}

func (h *Handler) ScanMemory(c *gin.Context) {
	h.jobs.Create(c, "MEMORY_FORENSICS_SCAN")
}

func (h *Handler) ListReports(c *gin.Context) {
	h.jobs.List(c)
}

func (h *Handler) GetReport(c *gin.Context) { h.jobs.Get(c, c.Param("id")) }
