package ueba

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct{ events operational.EventStore }

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.events = operational.EventStore{DB: db, Module: "UEBA"}
	g := p.Group("/ueba")
	g.POST("/events", middleware.RequirePermission(db, "THREAT_MANAGE"), h.SubmitEvent)
	g.GET("/events", middleware.RequirePermission(db, "THREAT_VIEW"), h.ListEvents)
	g.GET("/anomalies", middleware.RequirePermission(db, "THREAT_VIEW"), h.ListAnomalies)
}
func (h *Handler) SubmitEvent(c *gin.Context)   { h.events.Submit(c) }
func (h *Handler) ListEvents(c *gin.Context)    { h.events.List(c, 0) }
func (h *Handler) ListAnomalies(c *gin.Context) { h.events.List(c, 70) }
