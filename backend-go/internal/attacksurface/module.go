package attacksurface

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct{ store operational.AssessmentStore }

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.store = operational.AssessmentStore{DB: db, Module: "ATTACK_SURFACE"}
	g := p.Group("/attack-surface")
	g.GET("", middleware.RequirePermission(db, "ATTACK_SURFACE_VIEW"), h.ListSurface)
	g.GET("/:id", middleware.RequirePermission(db, "ATTACK_SURFACE_VIEW"), h.GetSurface)
	g.POST("/assess", middleware.RequirePermission(db, "ATTACK_SURFACE_ASSESS"), h.AssessSurface)
}
func (h *Handler) ListSurface(c *gin.Context)   { h.store.List(c) }
func (h *Handler) GetSurface(c *gin.Context)    { h.store.Get(c, c.Param("id")) }
func (h *Handler) AssessSurface(c *gin.Context) { h.store.Create(c) }
