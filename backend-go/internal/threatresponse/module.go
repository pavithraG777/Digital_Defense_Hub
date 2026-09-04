package threatresponse

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct {
	actions operational.ActionStore
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.actions = operational.ActionStore{DB: db, Module: "THREAT_RESPONSE"}
	g := p.Group("/threat-response")
	g.GET("", middleware.RequirePermission(db, "THREAT_RESPONSE_VIEW"), h.ListResponses)
	g.GET("/:id", middleware.RequirePermission(db, "THREAT_RESPONSE_VIEW"), h.GetResponse)
	g.GET("/actions", middleware.RequirePermission(db, "THREAT_RESPONSE_VIEW"), h.ListActions)
	g.POST("/activate", middleware.RequirePermission(db, "THREAT_RESPONSE_ACTIVATE"), h.ActivateResponse)
	g.POST("/review", middleware.RequirePermission(db, "THREAT_RESPONSE_REVIEW"), h.ReviewResponse)
}
func (h *Handler) ListResponses(c *gin.Context)    { h.actions.List(c) }
func (h *Handler) GetResponse(c *gin.Context)      { h.actions.Get(c, c.Param("id")) }
func (h *Handler) ActivateResponse(c *gin.Context) { h.actions.Create(c, "ACTIVATE") }
func (h *Handler) ReviewResponse(c *gin.Context)   { h.actions.Create(c, "REVIEW") }
func (h *Handler) ListActions(c *gin.Context)      { h.actions.List(c) }
