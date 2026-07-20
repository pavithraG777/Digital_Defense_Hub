package rolepermission

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

func (h *Handler) AssignPermissions(c *gin.Context) {

	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid role ID",
			err.Error(),
		)
		return
	}

	var grantedBy *uuid.UUID

	if userID, ok := getUUIDFromContext(c, "user_id"); ok {
		grantedBy = &userID
	}

	var req AssignPermissionsRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	result, err := h.service.AssignPermissions(
		c.Request.Context(),
		roleID,
		grantedBy,
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

		case errors.Is(err, ErrPermissionNotFound):
			response.NotFound(
				c,
				"Permission not found",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to assign permissions",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Permissions assigned successfully",
		result,
	)
}

func (h *Handler) ListRolePermissions(c *gin.Context) {

	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid role ID",
			err.Error(),
		)
		return
	}

	result, err := h.service.ListRolePermissions(
		c.Request.Context(),
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
				"Failed to fetch role permissions",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Role permissions retrieved successfully",
		result,
	)
}

func (h *Handler) RemovePermission(c *gin.Context) {

	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid role ID",
			err.Error(),
		)
		return
	}

	var req RemovePermissionRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	if req.PermissionID == uuid.Nil {
		response.BadRequest(
			c,
			"Invalid permission ID",
			"permission_id is required",
		)
		return
	}

	err = h.service.RemovePermission(
		c.Request.Context(),
		roleID,
		req.PermissionID,
	)
	if err != nil {
		response.BadRequest(
			c,
			"Failed to remove permission",
			err.Error(),
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Permission removed successfully",
		nil,
	)
}

func (h *Handler) ReplacePermissions(c *gin.Context) {

	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid role ID",
			err.Error(),
		)
		return
	}

	var req ReplacePermissionsRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		response.BadRequest(
			c,
			"User ID not found",
			"missing authenticated user",
		)
		return
	}

	grantedBy, ok := userID.(uuid.UUID)
	if !ok {
		response.BadRequest(
			c,
			"Invalid user ID",
			"user_id is not a valid UUID",
		)
		return
	}

	result, err := h.service.ReplacePermissions(
		c.Request.Context(),
		roleID,
		&grantedBy,
		req,
	)
	if err != nil {
		response.BadRequest(
			c,
			"Failed to replace permissions",
			err.Error(),
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Permissions replaced successfully",
		result,
	)
}
