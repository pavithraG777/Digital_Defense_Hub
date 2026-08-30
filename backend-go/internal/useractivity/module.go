package useractivity

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

	group := protected.Group("/user-activity")
	group.GET("", middleware.RequirePermission(databasePool, "USER_ACTIVITY_VIEW"), handler.ListActivities)
	group.GET(":id", middleware.RequirePermission(databasePool, "USER_ACTIVITY_VIEW"), handler.GetActivity)
	group.POST("/suspend", middleware.RequirePermission(databasePool, "USER_ACTIVITY_SUSPEND"), handler.SuspendUser)
	group.POST("/export", middleware.RequirePermission(databasePool, "USER_ACTIVITY_EXPORT"), handler.ExportActivity)
}

func (h *Handler) ListActivities(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []any{}})
}

func (h *Handler) GetActivity(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"id": c.Param("id")}})
}

func (h *Handler) SuspendUser(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "user suspension initiated"})
}

func (h *Handler) ExportActivity(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "activity export started"})
}
