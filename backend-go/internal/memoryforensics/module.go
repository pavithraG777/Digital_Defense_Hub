package memoryforensics

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

	routeGroup := protected.Group("/memoryforensics")
	routeGroup.POST("/scan", middleware.RequirePermission(databasePool, "MEMORY_FORENSICS_MANAGE"), handler.ScanMemory)
	routeGroup.GET("/reports", middleware.RequirePermission(databasePool, "MEMORY_FORENSICS_VIEW"), handler.ListReports)
}

func (h *Handler) ScanMemory(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "memory forensics scan started"})
}

func (h *Handler) ListReports(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "reports": []any{}})
}
