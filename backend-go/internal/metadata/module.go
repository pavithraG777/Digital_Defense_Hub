package metadata

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

	group := protected.Group("/metadata")
	group.POST("/validate", middleware.RequirePermission(databasePool, "ANALYSIS_EXECUTE"), handler.ValidateMetadata)
	group.GET("/:metadata_id", middleware.RequirePermission(databasePool, "ANALYSIS_VIEW"), handler.GetMetadata)
}

func (h *Handler) ValidateMetadata(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "metadata validation queued"})
}

func (h *Handler) GetMetadata(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"metadata_id": c.Param("metadata_id")}})
}
