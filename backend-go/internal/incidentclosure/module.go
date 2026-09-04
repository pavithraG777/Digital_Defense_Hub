package incidentclosure

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
	g := p.Group("/incident-closure")
	g.GET("", middleware.RequirePermission(db, "THREAT_VIEW"), h.GetIncidentClosure)
}
func (h *Handler) GetIncidentClosure(c *gin.Context) {
	operational.ListIncidentStage(c, h.db, "incident closure", []string{"CLOSED"})
}
