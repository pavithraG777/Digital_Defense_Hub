package integration

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct{ actions operational.ActionStore }

func NewHandler() *Handler {
	return &Handler{}
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}

	routeGroup := protected.Group("/integration")
	routeGroup.POST("/siem", middleware.RequirePermission(databasePool, "INTEGRATION_MANAGE"), handler.SendToSIEM)
	routeGroup.POST("/ticket", middleware.RequirePermission(databasePool, "INTEGRATION_MANAGE"), handler.CreateTicket)
	routeGroup.GET("/requests", middleware.RequirePermission(databasePool, "INTEGRATION_MANAGE"), handler.ListRequests)
	handler.actions = operational.ActionStore{DB: databasePool, Module: "INTEGRATION"}
}

func (h *Handler) SendToSIEM(c *gin.Context) {
	h.actions.Create(c, "SEND_TO_SIEM")
}

func (h *Handler) CreateTicket(c *gin.Context) {
	h.actions.Create(c, "CREATE_TICKET")
}

func (h *Handler) ListRequests(c *gin.Context) { h.actions.List(c) }
