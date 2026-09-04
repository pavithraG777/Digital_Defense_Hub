package insiderthreat

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
	h.events = operational.EventStore{DB: db, Module: "INSIDER_THREAT"}
	h.actions = operational.ActionStore{DB: db, Module: "INSIDER_THREAT"}
	g := p.Group("/insider-threat")
	g.GET("", middleware.RequirePermission(db, "INSIDER_THREAT_VIEW"), h.ListCases)
	g.GET("/:id", middleware.RequirePermission(db, "INSIDER_THREAT_VIEW"), h.GetCase)
	g.GET("/investigations", middleware.RequirePermission(db, "INSIDER_THREAT_VIEW"), h.ListInvestigations)
	g.POST("/alert", middleware.RequirePermission(db, "INSIDER_THREAT_ALERT"), h.RaiseAlert)
	g.POST("/investigate", middleware.RequirePermission(db, "INSIDER_THREAT_INVESTIGATE"), h.InvestigateCase)
}
func (h *Handler) ListCases(c *gin.Context)          { h.events.List(c, 0) }
func (h *Handler) GetCase(c *gin.Context)            { h.events.Get(c, c.Param("id")) }
func (h *Handler) RaiseAlert(c *gin.Context)         { h.events.Submit(c) }
func (h *Handler) InvestigateCase(c *gin.Context)    { h.actions.Create(c, "INVESTIGATE") }
func (h *Handler) ListInvestigations(c *gin.Context) { h.actions.List(c) }
