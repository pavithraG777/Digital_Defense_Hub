package role

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
	}
}

func getUUIDFromContext(
	c *gin.Context,
	key string,
) (uuid.UUID, bool) {
	value, exists := c.Get(key)
	if !exists {
		return uuid.Nil, false
	}

	id, ok := value.(uuid.UUID)
	if !ok {
		return uuid.Nil, false
	}

	return id, true
}

func (h *Handler) CreateRole(c *gin.Context) {
	organizationID, ok := getUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	var req CreateRoleRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	role, err := h.service.CreateRole(
		c.Request.Context(),
		organizationID,
		req,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrRoleCodeAlreadyExists):
			response.BadRequest(
				c,
				"Role code already exists",
				nil,
			)

		case errors.Is(err, ErrRoleNameAlreadyExists):
			response.BadRequest(
				c,
				"Role name already exists",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to create role",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusCreated,
		"Role created successfully",
		role,
	)
}

func (h *Handler) ListRoles(c *gin.Context) {
	organizationID, ok := getUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	var req ListRolesRequest

	if err := c.ShouldBindQuery(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid query parameters",
			err.Error(),
		)
		return
	}

	result, err := h.service.ListRoles(
		c.Request.Context(),
		organizationID,
		req,
	)
	if err != nil {
		response.BadRequest(
			c,
			"Failed to fetch roles",
			err.Error(),
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Roles retrieved successfully",
		result,
	)
}

func (h *Handler) GetRoleByID(c *gin.Context) {
	organizationID, ok := getUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid role ID",
			err.Error(),
		)
		return
	}

	role, err := h.service.GetRoleByID(
		c.Request.Context(),
		organizationID,
		roleID,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrRoleNotFound):
			response.NotFound(
				c,
				"Role not found",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to fetch role",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Role retrieved successfully",
		role,
	)
}

func (h *Handler) UpdateRole(c *gin.Context) {
	organizationID, ok := getUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid role ID",
			err.Error(),
		)
		return
	}

	var req UpdateRoleRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	updatedRole, err := h.service.UpdateRole(
		c.Request.Context(),
		organizationID,
		roleID,
		req,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrRoleNotFound):
			response.NotFound(
				c,
				"Role not found",
				nil,
			)

		case errors.Is(err, ErrRoleNameAlreadyExists):
			response.BadRequest(
				c,
				"Role name already exists",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to update role",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Role updated successfully",
		updatedRole,
	)
}

func (h *Handler) DeleteRole(c *gin.Context) {
	organizationID, ok := getUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid role ID",
			err.Error(),
		)
		return
	}

	err = h.service.DeleteRole(
		c.Request.Context(),
		organizationID,
		roleID,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrRoleNotFound):
			response.NotFound(
				c,
				"Role not found",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to delete role",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Role deleted successfully",
		nil,
	)
}
