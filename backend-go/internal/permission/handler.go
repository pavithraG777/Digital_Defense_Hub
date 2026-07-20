package permission

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
	if ok {
		return id, true
	}

	idString, ok := value.(string)
	if !ok {
		return uuid.Nil, false
	}

	id, err := uuid.Parse(idString)
	if err != nil {
		return uuid.Nil, false
	}

	return id, true
}

func (h *Handler) CreatePermission(c *gin.Context) {

	var req CreatePermissionRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	permission, err := h.service.CreatePermission(
		c.Request.Context(),
		req,
	)
	if err != nil {

		switch {

		case errors.Is(err, ErrPermissionCodeAlreadyExists):
			response.BadRequest(
				c,
				"Permission code already exists",
				nil,
			)

		case errors.Is(err, ErrPermissionActionAlreadyExists):
			response.BadRequest(
				c,
				"Permission already exists for this module and action",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to create permission",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusCreated,
		"Permission created successfully",
		permission,
	)
}

func (h *Handler) ListPermissions(c *gin.Context) {

	var req ListPermissionsRequest

	if err := c.ShouldBindQuery(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid query parameters",
			err.Error(),
		)
		return
	}

	result, err := h.service.ListPermissions(
		c.Request.Context(),
		req,
	)
	if err != nil {
		response.BadRequest(
			c,
			"Failed to fetch permissions",
			err.Error(),
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Permissions retrieved successfully",
		result,
	)
}

func (h *Handler) GetPermissionByID(c *gin.Context) {
	permissionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid permission ID",
			err.Error(),
		)
		return
	}

	permission, err := h.service.GetPermissionByID(
		c.Request.Context(),
		permissionID,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrPermissionNotFound):
			response.NotFound(
				c,
				"Permission not found",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to fetch permission",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Permission retrieved successfully",
		permission,
	)
}

func (h *Handler) UpdatePermission(c *gin.Context) {

	permissionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid permission ID",
			err.Error(),
		)
		return
	}

	var req UpdatePermissionRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	permission, err := h.service.UpdatePermission(
		c.Request.Context(),
		permissionID,
		req,
	)
	if err != nil {

		switch {

		case errors.Is(err, ErrPermissionNotFound):
			response.NotFound(
				c,
				"Permission not found",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to update permission",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Permission updated successfully",
		permission,
	)
}

func (h *Handler) DeletePermission(c *gin.Context) {
	permissionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid permission ID",
			err.Error(),
		)
		return
	}

	err = h.service.DeletePermission(
		c.Request.Context(),
		permissionID,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrPermissionNotFound):
			response.NotFound(
				c,
				"Permission not found",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to delete permission",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Permission deactivated successfully",
		nil,
	)
}
