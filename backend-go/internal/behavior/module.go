package behavior

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
	h.events = operational.EventStore{DB: db, Module: "BEHAVIOR"}
	g := p.Group("/behavior")
	g.POST("/events", middleware.RequirePermission(db, "THREAT_MANAGE"), h.SubmitBehaviorEvent)
	g.GET("/events", middleware.RequirePermission(db, "THREAT_VIEW"), h.ListEvents)
	g.GET("/baselines/:user_id", middleware.RequirePermission(db, "THREAT_VIEW"), h.GetBaseline)
}
func (h *Handler) SubmitBehaviorEvent(c *gin.Context) { h.events.Submit(c) }
func (h *Handler) ListEvents(c *gin.Context)          { h.events.List(c, 0) }
func (h *Handler) GetBaseline(c *gin.Context)         { h.events.Baseline(c, c.Param("user_id")) }
