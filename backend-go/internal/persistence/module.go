package persistence

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
	h.store = operational.AssessmentStore{DB: db, Module: "PERSISTENCE"}
	g := p.Group("/persistence")
	g.GET("/checks", middleware.RequirePermission(db, "PERSISTENCE_VIEW"), h.ListChecks)
	g.GET("/checks/:id", middleware.RequirePermission(db, "PERSISTENCE_VIEW"), h.GetCheck)
	g.POST("/discover", middleware.RequirePermission(db, "PERSISTENCE_MANAGE"), h.DiscoverPersistence)
}
func (h *Handler) ListChecks(c *gin.Context)          { h.store.List(c) }
func (h *Handler) GetCheck(c *gin.Context)            { h.store.Get(c, c.Param("id")) }
func (h *Handler) DiscoverPersistence(c *gin.Context) { h.store.Create(c) }
