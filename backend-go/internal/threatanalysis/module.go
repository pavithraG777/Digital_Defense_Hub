package threatanalysis

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}

	group := protected.Group("/threat-analysis")
	group.GET("", middleware.RequirePermission(databasePool, "THREAT_ANALYSIS_VIEW"), handler.ListAnalyses)
	group.GET(":id", middleware.RequirePermission(databasePool, "THREAT_ANALYSIS_VIEW"), handler.GetAnalysis)
	group.POST("/run", middleware.RequirePermission(databasePool, "THREAT_ANALYSIS_RUN"), handler.RunAnalysis)
	group.POST("/close", middleware.RequirePermission(databasePool, "THREAT_ANALYSIS_CLOSE"), handler.CloseAnalysis)
}

func (h *Handler) ListAnalyses(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []any{}})
}

func (h *Handler) GetAnalysis(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"id": c.Param("id")}})
}

func (h *Handler) RunAnalysis(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "threat analysis started"})
}

func (h *Handler) CloseAnalysis(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "threat analysis closed"})
}
