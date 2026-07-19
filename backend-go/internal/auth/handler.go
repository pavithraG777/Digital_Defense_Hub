package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
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

func (h *Handler) Login(c *gin.Context) {
	var request LoginRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	loginResponse, err := h.service.Login(
		c.Request.Context(),
		request,
	)

	if err != nil {

		switch {

		case errors.Is(err, ErrInvalidCredentials):
			response.Unauthorized(
				c,
				err.Error(),
				nil,
			)

		case errors.Is(err, ErrAccountPending),
			errors.Is(err, ErrAccountInactive),
			errors.Is(err, ErrAccountSuspended),
			errors.Is(err, ErrAccountLocked),
			errors.Is(err, ErrNoActiveRoles):

			response.Error(
				c,
				http.StatusForbidden,
				err.Error(),
				nil,
			)

		default:
			response.InternalServerError(
				c,
				"Login failed",
				err.Error(),
			)
		}

		return
	}

	response.OK(
		c,
		"Login successful",
		loginResponse,
	)
}
func (h *Handler) Profile(c *gin.Context) {
	response.Success(
		c,
		http.StatusOK,
		"Profile retrieved successfully",
		gin.H{
			"user_id":         c.MustGet("user_id"),
			"organization_id": c.MustGet("organization_id"),
			"username":        c.MustGet("username"),
			"roles":           c.MustGet("roles"),
			"token_id":        c.MustGet("token_id"),
		},
	)
}
