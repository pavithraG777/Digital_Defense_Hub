package usb

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

	routeGroup := protected.Group("/usb")
	routeGroup.GET("/devices", middleware.RequirePermission(databasePool, "USB_VIEW"), handler.ListDevices)
	routeGroup.POST("/devices/block", middleware.RequirePermission(databasePool, "USB_BLOCK"), handler.BlockDevice)
	routeGroup.POST("/policy", middleware.RequirePermission(databasePool, "USB_MANAGE"), handler.UpdatePolicy)
}

func (h *Handler) ListDevices(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "devices": []any{}})
}

func (h *Handler) BlockDevice(c *gin.Context) {
	c.JSON(202, gin.H{"success": true, "message": "USB device block request accepted"})
}

func (h *Handler) UpdatePolicy(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "message": "USB protection policy updated"})
}
