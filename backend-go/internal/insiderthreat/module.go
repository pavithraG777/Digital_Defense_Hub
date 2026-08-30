package insiderthreat

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

	group := protected.Group("/insider-threat")
	group.GET("", middleware.RequirePermission(databasePool, "INSIDER_THREAT_VIEW"), handler.ListCases)
	group.GET("/:id", middleware.RequirePermission(databasePool, "INSIDER_THREAT_VIEW"), handler.GetCase)
	group.POST("/alert", middleware.RequirePermission(databasePool, "INSIDER_THREAT_ALERT"), handler.RaiseAlert)
	group.POST("/investigate", middleware.RequirePermission(databasePool, "INSIDER_THREAT_INVESTIGATE"), handler.InvestigateCase)
}

func (h *Handler) ListCases(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []any{}})
}

func (h *Handler) GetCase(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"id": c.Param("id")}})
}

func (h *Handler) RaiseAlert(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "insider threat alert raised"})
}

func (h *Handler) InvestigateCase(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "insider threat investigation started"})
}
