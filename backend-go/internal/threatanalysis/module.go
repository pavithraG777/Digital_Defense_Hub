package threatanalysis

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct {
	events  operational.EventStore
	actions operational.ActionStore
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.events = operational.EventStore{DB: db, Module: "THREAT_ANALYSIS"}
	h.actions = operational.ActionStore{DB: db, Module: "THREAT_ANALYSIS"}
	g := p.Group("/threat-analysis")
	g.GET("", middleware.RequirePermission(db, "THREAT_ANALYSIS_VIEW"), h.ListAnalyses)
	g.GET("/:id", middleware.RequirePermission(db, "THREAT_ANALYSIS_VIEW"), h.GetAnalysis)
	g.GET("/actions", middleware.RequirePermission(db, "THREAT_ANALYSIS_VIEW"), h.ListActions)
	g.POST("/run", middleware.RequirePermission(db, "THREAT_ANALYSIS_RUN"), h.RunAnalysis)
	g.POST("/close", middleware.RequirePermission(db, "THREAT_ANALYSIS_CLOSE"), h.CloseAnalysis)
}
func (h *Handler) ListAnalyses(c *gin.Context)  { h.events.List(c, 0) }
func (h *Handler) GetAnalysis(c *gin.Context)   { h.events.Get(c, c.Param("id")) }
func (h *Handler) RunAnalysis(c *gin.Context)   { h.events.Submit(c) }
func (h *Handler) CloseAnalysis(c *gin.Context) { h.actions.Create(c, "CLOSE_ANALYSIS") }
func (h *Handler) ListActions(c *gin.Context)   { h.actions.List(c) }
