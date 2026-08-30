package securityscore

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type Handler struct {
	service *Service
}

func RegisterRoutes(protected *gin.RouterGroup, db *pgxpool.Pool) {
	if protected == nil || db == nil {
		return
	}
	handler := &Handler{service: NewService(NewRepository(db))}
	group := protected.Group("/security-scores")
	group.GET("/organization", middleware.RequirePermission(db, "DASHBOARD_VIEW"), handler.Organization)
	group.GET("/organizations", middleware.RequirePermission(db, "ORGANIZATION_MANAGE"), handler.Organizations)
	group.GET("/threats", middleware.RequirePermission(db, "DASHBOARD_VIEW"), handler.Threats)
}

func (h *Handler) Organization(c *gin.Context) {
	organizationID, ok := contextOrganizationID(c)
	if !ok {
		response.Unauthorized(c, "Organization information is missing", nil)
		return
	}
	result, err := h.service.Organization(c.Request.Context(), organizationID)
	if err != nil {
		response.InternalServerError(c, "Unable to calculate organization security score", err.Error())
		return
	}
	response.OK(c, "Organization security score retrieved successfully", result)
}

func (h *Handler) Organizations(c *gin.Context) {
	result, err := h.service.Organizations(c.Request.Context())
	if err != nil {
		response.InternalServerError(c, "Unable to calculate organization security scores", err.Error())
		return
	}
	response.OK(c, "Organization security scores retrieved successfully", result)
}

func (h *Handler) Threats(c *gin.Context) {
	organizationID, ok := contextOrganizationID(c)
	if !ok {
		response.Unauthorized(c, "Organization information is missing", nil)
		return
	}
	result, err := h.service.Threats(c.Request.Context(), organizationID)
	if err != nil {
		response.InternalServerError(c, "Unable to retrieve threat score", err.Error())
		return
	}
	response.OK(c, "Threat score retrieved successfully", result)
}

func contextOrganizationID(c *gin.Context) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}
	value, exists := c.Get("organization_id")
	if !exists {
		return uuid.Nil, false
	}
	switch typed := value.(type) {
	case uuid.UUID:
		return typed, typed != uuid.Nil
	case string:
		parsed, err := uuid.Parse(strings.TrimSpace(typed))
		return parsed, err == nil && parsed != uuid.Nil
	default:
		return uuid.Nil, false
	}
}
