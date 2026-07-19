package user

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

func (h *Handler) CreateUser(c *gin.Context) {
	var request CreateUserRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

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

	assignedBy, ok := getUUIDFromContext(
		c,
		"user_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return
	}

	createdUser, err := h.service.CreateUser(
		c.Request.Context(),
		organizationID,
		assignedBy,
		request,
	)

	if err != nil {
		switch {
		case errors.Is(err, ErrUsernameAlreadyExists),
			errors.Is(err, ErrEmailAlreadyExists),
			errors.Is(err, ErrInvalidUserType):

			response.BadRequest(
				c,
				err.Error(),
				nil,
			)

		case errors.Is(err, ErrRoleNotFound):
			response.Error(
				c,
				http.StatusNotFound,
				err.Error(),
				nil,
			)

		default:
			response.InternalServerError(
				c,
				"Failed to create user",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusCreated,
		"User created successfully",
		createdUser,
	)
}

func getUUIDFromContext(
	c *gin.Context,
	key string,
) (uuid.UUID, bool) {
	value, exists := c.Get(key)
	if !exists {
		return uuid.Nil, false
	}

	switch typedValue := value.(type) {
	case uuid.UUID:
		return typedValue, true

	case string:
		parsedValue, err := uuid.Parse(typedValue)
		if err != nil {
			return uuid.Nil, false
		}

		return parsedValue, true

	default:
		return uuid.Nil, false
	}
}
func (h *Handler) ListUsers(c *gin.Context) {
	var req ListUsersRequest

	if err := c.ShouldBindQuery(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid query parameters",
			err.Error(),
		)
		return
	}

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

	users, err := h.service.ListUsers(
		c.Request.Context(),
		organizationID,
		req,
	)
	if err != nil {
		response.InternalServerError(
			c,
			"Failed to retrieve users",
			err.Error(),
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Users retrieved successfully",
		users,
	)
}

func (h *Handler) GetUserByID(c *gin.Context) {
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

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid user ID",
			err.Error(),
		)
		return
	}

	userDetails, err := h.service.GetUserByID(
		c.Request.Context(),
		organizationID,
		userID,
	)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			response.NotFound(
				c,
				"User not found",
				nil,
			)
			return
		}

		response.InternalServerError(
			c,
			"Failed to retrieve user",
			err.Error(),
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"User retrieved successfully",
		userDetails,
	)
}

func (h *Handler) UpdateUser(c *gin.Context) {
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

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(
			c,
			"Invalid user ID",
			err.Error(),
		)
		return
	}

	var req UpdateUserRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	updatedUser, err := h.service.UpdateUser(
		c.Request.Context(),
		organizationID,
		userID,
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

		case errors.Is(err, ErrEmailAlreadyExists):
			response.BadRequest(
				c,
				"Official email already exists",
				nil,
			)

		default:
			response.BadRequest(
				c,
				"Failed to update user",
				err.Error(),
			)
		}

		return
	}

	response.Success(
		c,
		http.StatusOK,
		"User updated successfully",
		updatedUser,
	)
}
