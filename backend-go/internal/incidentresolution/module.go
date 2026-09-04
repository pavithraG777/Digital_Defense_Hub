package incidentresolution

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct{ db *pgxpool.Pool }

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.db = db
	g := p.Group("/incident-resolution")
	g.GET("", middleware.RequirePermission(db, "THREAT_VIEW"), h.GetIncidentResolution)
}
func (h *Handler) GetIncidentResolution(c *gin.Context) {
	operational.ListIncidentStage(c, h.db, "incident resolution", []string{"RESOLVED"})
}
