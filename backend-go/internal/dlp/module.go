package dlp

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
	h.events = operational.EventStore{DB: db, Module: "DLP"}
	g := p.Group("/dlp")
	g.POST("/events", middleware.RequirePermission(db, "THREAT_MANAGE"), h.SubmitDLPEvent)
	g.GET("/events", middleware.RequirePermission(db, "THREAT_VIEW"), h.ListDLPEvents)
}
func (h *Handler) SubmitDLPEvent(c *gin.Context) { h.events.Submit(c) }
func (h *Handler) ListDLPEvents(c *gin.Context)  { h.events.List(c, 0) }
