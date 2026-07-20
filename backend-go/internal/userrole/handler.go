package userrole

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

func (h *Handler) AssignRoles(c *gin.Context) {

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid user ID",
			err.Error(),
		)
		return
	}

	var grantedBy *uuid.UUID

	if authenticatedUserID, ok := getUUIDFromContext(
		c,
		"user_id",
	); ok {
		grantedBy = &authenticatedUserID
	}

	var req AssignRolesRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	result, err := h.service.AssignRoles(
		c.Request.Context(),
		userID,
		grantedBy,
		req,
	)
	if err != nil {

		switch {

		case errors.Is(err, ErrUserNotFound):
			response.NotFound(
				c,
				"User not found",
				nil,
			)

		case errors.Is(err, ErrRoleNotFound):
			response.NotFound(
				c,
				"Role not found",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to assign roles",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Roles assigned successfully",
		result,
	)
}

func (h *Handler) ListUserRoles(c *gin.Context) {

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid user ID",
			err.Error(),
		)
		return
	}

	result, err := h.service.ListUserRoles(
		c.Request.Context(),
		userID,
	)
	if err != nil {

		switch {

		case errors.Is(err, ErrUserNotFound):
			response.NotFound(
				c,
				"User not found",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to fetch user roles",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"User roles retrieved successfully",
		result,
	)
}

func (h *Handler) RemoveRole(c *gin.Context) {

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid user ID",
			err.Error(),
		)
		return
	}

	var req RemoveRoleRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	if req.RoleID == uuid.Nil {
		response.BadRequest(
			c,
			"Invalid role ID",
			"role_id is required",
		)
		return
	}

	err = h.service.RemoveRole(
		c.Request.Context(),
		userID,
		req.RoleID,
	)
	if err != nil {
		response.BadRequest(
			c,
			"Failed to remove role",
			err.Error(),
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Role removed successfully",
		nil,
	)
}

func (h *Handler) ReplaceRoles(c *gin.Context) {

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid user ID",
			err.Error(),
		)
		return
	}

	var req ReplaceRolesRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	authenticatedUserID, exists := c.Get("user_id")
	if !exists {
		response.BadRequest(
			c,
			"User ID not found",
			"missing authenticated user",
		)
		return
	}

	grantedBy, ok := authenticatedUserID.(uuid.UUID)
	if !ok {

		userIDString, stringOK := authenticatedUserID.(string)
		if !stringOK {
			response.BadRequest(
				c,
				"Invalid user ID",
				"user_id is not a valid UUID",
			)
			return
		}

		parsedUserID, parseErr := uuid.Parse(userIDString)
		if parseErr != nil {
			response.BadRequest(
				c,
				"Invalid user ID",
				"user_id is not a valid UUID",
			)
			return
		}

		grantedBy = parsedUserID
	}

	result, err := h.service.ReplaceRoles(
		c.Request.Context(),
		userID,
		&grantedBy,
		req,
	)
	if err != nil {

		switch {

		case errors.Is(err, ErrUserNotFound):
			response.NotFound(
				c,
				"User not found",
				nil,
			)

		case errors.Is(err, ErrRoleNotFound):
			response.NotFound(
				c,
				"Role not found",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to replace roles",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Roles replaced successfully",
		result,
	)
}
