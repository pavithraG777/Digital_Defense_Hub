package securitymonitoring

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
	h.events = operational.EventStore{DB: db, Module: "SECURITY_MONITORING"}
	h.actions = operational.ActionStore{DB: db, Module: "SECURITY_MONITORING"}
	g := p.Group("/security-monitoring")
	g.GET("", middleware.RequirePermission(db, "SECURITY_MONITORING_VIEW"), h.ListMonitors)
	g.GET("/:id", middleware.RequirePermission(db, "SECURITY_MONITORING_VIEW"), h.GetMonitor)
	g.GET("/silence-actions", middleware.RequirePermission(db, "SECURITY_MONITORING_VIEW"), h.ListSilenceActions)
	g.POST("/alerts", middleware.RequirePermission(db, "SECURITY_MONITORING_ALERTS"), h.CreateAlert)
	g.POST("/silence", middleware.RequirePermission(db, "SECURITY_MONITORING_SILENCE"), h.SilenceAlert)
}
func (h *Handler) ListMonitors(c *gin.Context)       { h.events.List(c, 0) }
func (h *Handler) GetMonitor(c *gin.Context)         { h.events.Get(c, c.Param("id")) }
func (h *Handler) CreateAlert(c *gin.Context)        { h.events.Submit(c) }
func (h *Handler) SilenceAlert(c *gin.Context)       { h.actions.Create(c, "SILENCE_ALERT") }
func (h *Handler) ListSilenceActions(c *gin.Context) { h.actions.List(c) }
