package middleware

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
)

func ValidateSession(
	repository *auth.Repository,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := contextUUID(
			c,
			"user_id",
		)
		if err != nil {
			abortSessionRequest(
				c,
				"Invalid user authentication context",
			)
			return
		}

		organizationID, err := contextUUID(
			c,
			"organization_id",
		)
		if err != nil {
			abortSessionRequest(
				c,
				"Invalid organization authentication context",
			)
			return
		}

		sessionID, err := contextUUID(
			c,
			"token_id",
		)
		if err != nil {
			abortSessionRequest(
				c,
				"Invalid session authentication context",
			)
			return
		}

		err = repository.ValidateSession(
			c.Request.Context(),
			sessionID,
			userID,
			organizationID,
		)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrSessionNotFound):
				abortSessionRequest(
					c,
					"Authentication session was not found",
				)

			case errors.Is(err, auth.ErrSessionInactive):
				abortSessionRequest(
					c,
					"Authentication session is no longer active",
				)

			case errors.Is(err, auth.ErrSessionExpired):
				abortSessionRequest(
					c,
					"Authentication session has expired",
				)

			case errors.Is(err, auth.ErrSessionMismatch):
				abortSessionRequest(
					c,
					"Authentication session is invalid",
				)

			case errors.Is(err, auth.ErrSessionMFAUnverified):
				abortSessionRequest(c, "MFA verification is required")

			default:
				c.AbortWithStatusJSON(
					http.StatusInternalServerError,
					gin.H{
						"success": false,
						"message": "Failed to validate authentication session",
						"error":   err.Error(),
					},
				)
			}

			return
		}

		err = repository.UpdateSessionActivity(
			c.Request.Context(),
			sessionID,
			userID,
			organizationID,
		)
		if err != nil {
			if errors.Is(
				err,
				auth.ErrSessionInactive,
			) {
				abortSessionRequest(
					c,
					"Authentication session is no longer active",
				)
				return
			}

			c.AbortWithStatusJSON(
				http.StatusInternalServerError,
				gin.H{
					"success": false,
					"message": "Failed to update session activity",
					"error":   err.Error(),
				},
			)
			return
		}

		c.Next()
	}
}

func contextUUID(
	c *gin.Context,
	key string,
) (uuid.UUID, error) {
	value, exists := c.Get(key)
	if !exists {
		return uuid.Nil, fmt.Errorf(
			"%s was not found in request context",
			key,
		)
	}

	switch typedValue := value.(type) {
	case uuid.UUID:
		if typedValue == uuid.Nil {
			return uuid.Nil, fmt.Errorf(
				"%s is empty",
				key,
			)
		}

		return typedValue, nil

	case string:
		parsedValue, err := uuid.Parse(
			typedValue,
		)
		if err != nil {
			return uuid.Nil, fmt.Errorf(
				"%s is not a valid UUID: %w",
				key,
				err,
			)
		}

		return parsedValue, nil

	default:
		return uuid.Nil, fmt.Errorf(
			"%s has unsupported type %T",
			key,
			value,
		)
	}
}

func abortSessionRequest(
	c *gin.Context,
	message string,
) {
	c.AbortWithStatusJSON(
		http.StatusUnauthorized,
		gin.H{
			"success": false,
			"message": message,
		},
	)
}
