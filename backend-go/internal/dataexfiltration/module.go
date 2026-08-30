package dataexfiltration

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

	group := protected.Group("/data-exfiltration")
	group.GET("", middleware.RequirePermission(databasePool, "DATA_EXFILTRATION_VIEW"), handler.ListCases)
	group.GET(":id", middleware.RequirePermission(databasePool, "DATA_EXFILTRATION_VIEW"), handler.GetCase)
	group.POST("/investigate", middleware.RequirePermission(databasePool, "DATA_EXFILTRATION_INVESTIGATE"), handler.InvestigateCase)
	group.POST("/contain", middleware.RequirePermission(databasePool, "DATA_EXFILTRATION_CONTAIN"), handler.ContainCase)
}

func (h *Handler) ListCases(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []any{}})
}

func (h *Handler) GetCase(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"id": c.Param("id")}})
}

func (h *Handler) InvestigateCase(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "data exfiltration investigation started"})
}

func (h *Handler) ContainCase(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "data exfiltration containment started"})
}
