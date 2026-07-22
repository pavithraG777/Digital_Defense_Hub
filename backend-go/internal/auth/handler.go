package auth

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

// Login authenticates the user and returns an access token
// together with a refresh token.
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

// RefreshAccessToken validates and rotates the supplied refresh token.
// It returns a new access token and a new refresh token.
func (h *Handler) RefreshAccessToken(c *gin.Context) {
	var request RefreshTokenRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	refreshResponse, err :=
		h.service.RefreshAccessToken(
			c.Request.Context(),
			request,
		)

	if err != nil {
		switch {
		case errors.Is(err, ErrRefreshTokenNotFound):
			response.Unauthorized(
				c,
				"Refresh token is invalid",
				nil,
			)

		case errors.Is(err, ErrRefreshTokenInactive):
			response.Unauthorized(
				c,
				"Refresh token is inactive or already used",
				nil,
			)

		case errors.Is(err, ErrRefreshTokenExpired):
			response.Unauthorized(
				c,
				"Refresh token has expired",
				nil,
			)

		case errors.Is(err, ErrRefreshSessionMismatch),
			errors.Is(err, ErrSessionNotFound),
			errors.Is(err, ErrSessionInactive),
			errors.Is(err, ErrSessionExpired),
			errors.Is(err, ErrSessionMismatch):

			response.Unauthorized(
				c,
				"Refresh token session is invalid",
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

		case errors.Is(err, ErrUserNotFound),
			errors.Is(err, ErrInvalidCredentials):

			response.Unauthorized(
				c,
				"Refresh token user is invalid",
				nil,
			)

		default:
			response.InternalServerError(
				c,
				"Token refresh failed",
				err.Error(),
			)
		}

		return
	}

	response.OK(
		c,
		"Token refreshed successfully",
		refreshResponse,
	)
}

// RevokeRefreshToken revokes one supplied refresh token.
func (h *Handler) RevokeRefreshToken(c *gin.Context) {
	var request RevokeRefreshTokenRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	err := h.service.RevokeRefreshToken(
		c.Request.Context(),
		request,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrRefreshTokenNotFound):
			response.Unauthorized(
				c,
				"Refresh token is invalid",
				nil,
			)

		case errors.Is(err, ErrRefreshTokenInactive):
			response.Unauthorized(
				c,
				"Refresh token is inactive or already revoked",
				nil,
			)

		case errors.Is(err, ErrRefreshTokenExpired):
			response.Unauthorized(
				c,
				"Refresh token has expired",
				nil,
			)

		default:
			response.InternalServerError(
				c,
				"Refresh token revocation failed",
				err.Error(),
			)
		}

		return
	}

	response.OK(
		c,
		"Refresh token revoked successfully",
		nil,
	)
}

// Profile returns authentication information stored
// in the Gin request context.
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

// Logout terminates the current authentication session
// and revokes every refresh token belonging to that session.
func (h *Handler) Logout(c *gin.Context) {
	userID, err := getUUIDFromContext(
		c,
		"user_id",
	)
	if err != nil {
		response.Unauthorized(
			c,
			"Invalid user authentication context",
			err.Error(),
		)
		return
	}

	organizationID, err := getUUIDFromContext(
		c,
		"organization_id",
	)
	if err != nil {
		response.Unauthorized(
			c,
			"Invalid organization authentication context",
			err.Error(),
		)
		return
	}

	sessionID, err := getUUIDFromContext(
		c,
		"token_id",
	)
	if err != nil {
		response.Unauthorized(
			c,
			"Invalid session authentication context",
			err.Error(),
		)
		return
	}

	err = h.service.Logout(
		c.Request.Context(),
		userID,
		organizationID,
		sessionID,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrSessionNotFound),
			errors.Is(err, ErrSessionInactive),
			errors.Is(err, ErrSessionExpired),
			errors.Is(err, ErrSessionMismatch):

			response.Unauthorized(
				c,
				"Session is invalid, expired, or already terminated",
				nil,
			)

		default:
			response.InternalServerError(
				c,
				"Logout failed",
				err.Error(),
			)
		}

		return
	}

	response.OK(
		c,
		"Logout successful",
		nil,
	)
}

// LogoutAllSessions terminates every active session
// and revokes every active refresh token belonging to the user.
func (h *Handler) LogoutAllSessions(c *gin.Context) {
	userID, err := getUUIDFromContext(
		c,
		"user_id",
	)
	if err != nil {
		response.Unauthorized(
			c,
			"Invalid user authentication context",
			err.Error(),
		)
		return
	}

	err = h.service.LogoutAllSessions(
		c.Request.Context(),
		userID,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			response.Unauthorized(
				c,
				"Authenticated user was not found",
				nil,
			)

		default:
			response.InternalServerError(
				c,
				"Logout from all devices failed",
				err.Error(),
			)
		}

		return
	}

	response.OK(
		c,
		"Logged out from all devices successfully",
		nil,
	)
}

// ChangePassword verifies the current password, updates it,
// and terminates all active sessions belonging to the user.
func (h *Handler) ChangePassword(c *gin.Context) {
	userID, err := getUUIDFromContext(
		c,
		"user_id",
	)
	if err != nil {
		response.Unauthorized(
			c,
			"Invalid user authentication context",
			err.Error(),
		)
		return
	}

	organizationID, err := getUUIDFromContext(
		c,
		"organization_id",
	)
	if err != nil {
		response.Unauthorized(
			c,
			"Invalid organization authentication context",
			err.Error(),
		)
		return
	}

	var request ChangePasswordRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	changePasswordResponse, err :=
		h.service.ChangePassword(
			c.Request.Context(),
			userID,
			organizationID,
			request,
		)

	if err != nil {
		switch {
		case errors.Is(
			err,
			ErrCurrentPasswordIncorrect,
		):
			response.Unauthorized(
				c,
				err.Error(),
				nil,
			)

		case errors.Is(
			err,
			ErrNewPasswordMismatch,
		),
			errors.Is(
				err,
				ErrNewPasswordSame,
			),
			errors.Is(
				err,
				ErrWeakPassword,
			):

			response.BadRequest(
				c,
				err.Error(),
				nil,
			)

		case errors.Is(
			err,
			ErrUserNotFound,
		):
			response.Unauthorized(
				c,
				"Authenticated user was not found",
				nil,
			)

		case errors.Is(
			err,
			ErrAccountPending,
		),
			errors.Is(
				err,
				ErrAccountInactive,
			),
			errors.Is(
				err,
				ErrAccountSuspended,
			),
			errors.Is(
				err,
				ErrAccountLocked,
			):

			response.Error(
				c,
				http.StatusForbidden,
				err.Error(),
				nil,
			)

		default:
			response.InternalServerError(
				c,
				"Password change failed",
				err.Error(),
			)
		}

		return
	}

	response.OK(
		c,
		"Password changed successfully. Please login again",
		changePasswordResponse,
	)
}

func (h *Handler) ForgotPassword(
	c *gin.Context,
) {
	var request ForgotPasswordRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request",
			err.Error(),
		)
		return
	}

	result, err := h.service.ForgotPassword(
		c.Request.Context(),
		request,
	)

	if err != nil {
		response.BadRequest(
			c,
			err.Error(),
			nil,
		)
		return
	}

	response.Success(
		c,
		http.StatusOK,
		"Password reset request created successfully",
		result,
	)
}

func (h *Handler) ResetPassword(
	c *gin.Context,
) {
	var request ResetPasswordRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request",
			err.Error(),
		)
		return
	}

	result, err := h.service.ResetPassword(
		c.Request.Context(),
		request,
	)

	if err != nil {
		response.BadRequest(
			c,
			err.Error(),
			nil,
		)
		return
	}
	response.Success(
		c,
		http.StatusOK,
		"Password reset successfully",
		result,
	)
}

func getUUIDFromContext(
	c *gin.Context,
	key string,
) (uuid.UUID, error) {
	value, exists := c.Get(key)
	if !exists {
		return uuid.Nil, errors.New(
			key + " not found in request context",
		)
	}

	switch typedValue := value.(type) {
	case uuid.UUID:
		if typedValue == uuid.Nil {
			return uuid.Nil, errors.New(
				key + " is empty",
			)
		}

		return typedValue, nil

	case string:
		parsedValue, err := uuid.Parse(typedValue)
		if err != nil {
			return uuid.Nil, errors.New(
				key + " is not a valid UUID",
			)
		}

		return parsedValue, nil

	default:
		return uuid.Nil, errors.New(
			key + " has an invalid data type",
		)
	}
}
