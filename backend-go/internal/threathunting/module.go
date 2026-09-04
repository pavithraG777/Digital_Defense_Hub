package threathunting

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
	h.events = operational.EventStore{DB: db, Module: "THREAT_HUNTING"}
	h.actions = operational.ActionStore{DB: db, Module: "THREAT_HUNTING"}
	g := p.Group("/threat-hunting")
	g.GET("", middleware.RequirePermission(db, "THREAT_HUNTING_VIEW"), h.ListHunts)
	g.GET("/:id", middleware.RequirePermission(db, "THREAT_HUNTING_VIEW"), h.GetHunt)
	g.GET("/actions", middleware.RequirePermission(db, "THREAT_HUNTING_VIEW"), h.ListActions)
	g.POST("/search", middleware.RequirePermission(db, "THREAT_HUNTING_SEARCH"), h.SearchAlerts)
	g.POST("/investigate", middleware.RequirePermission(db, "THREAT_HUNTING_INVESTIGATE"), h.Investigate)
}
func (h *Handler) ListHunts(c *gin.Context)    { h.events.List(c, 0) }
func (h *Handler) GetHunt(c *gin.Context)      { h.events.Get(c, c.Param("id")) }
func (h *Handler) SearchAlerts(c *gin.Context) { h.events.Submit(c) }
func (h *Handler) Investigate(c *gin.Context)  { h.actions.Create(c, "INVESTIGATE") }
func (h *Handler) ListActions(c *gin.Context)  { h.actions.List(c) }
