package cloud

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
	h.store = operational.AssessmentStore{DB: db, Module: "CLOUD_MOBILE"}
	g := p.Group("/cloud")
	g.POST("/analyze", middleware.RequirePermission(db, "ANALYSIS_EXECUTE"), h.AnalyzeCloud)
	g.GET("", middleware.RequirePermission(db, "ANALYSIS_VIEW"), h.ListCloudAnalysis)
	g.GET("/:cloud_id", middleware.RequirePermission(db, "ANALYSIS_VIEW"), h.GetCloudAnalysis)
}
func (h *Handler) AnalyzeCloud(c *gin.Context)      { h.store.Create(c) }
func (h *Handler) ListCloudAnalysis(c *gin.Context) { h.store.List(c) }
func (h *Handler) GetCloudAnalysis(c *gin.Context)  { h.store.Get(c, c.Param("cloud_id")) }
