package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
)

// PasswordChangeRequirementReader provides the current password-change state
// for the authenticated identity. It is intentionally an interface so the
// enforcement middleware can be exercised without a database.
type PasswordChangeRequirementReader interface {
	RequiresPasswordChange(
		ctx context.Context,
		userID uuid.UUID,
		organizationID uuid.UUID,
	) (bool, error)
}

// EnforcePasswordChange restricts a user flagged with must_change_password to
// password completion and session-management endpoints. This uses the current
// database value rather than a JWT claim so an existing token cannot bypass a
// newly applied password-change requirement.
func EnforcePasswordChange(
	reader PasswordChangeRequirementReader,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		if reader == nil {
			c.AbortWithStatusJSON(
				http.StatusInternalServerError,
				gin.H{
					"success": false,
					"message": "Unable to verify password-change requirement",
				},
			)
			return
		}

		userID, err := contextUUID(c, "user_id")
		if err != nil {
			abortSessionRequest(c, "Invalid user authentication context")
			return
		}

		organizationID, err := contextUUID(c, "organization_id")
		if err != nil {
			abortSessionRequest(c, "Invalid organization authentication context")
			return
		}

		mustChangePassword, err := reader.RequiresPasswordChange(
			c.Request.Context(),
			userID,
			organizationID,
		)
		if err != nil {
			if errors.Is(err, auth.ErrUserNotFound) {
				abortSessionRequest(c, "Authenticated user was not found")
				return
			}

			c.AbortWithStatusJSON(
				http.StatusInternalServerError,
				gin.H{
					"success": false,
					"message": "Unable to verify password-change requirement",
				},
			)
			return
		}

		if !mustChangePassword || isPasswordChangeAllowedRoute(c.FullPath()) {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(
			http.StatusForbidden,
			gin.H{
				"success": false,
				"message": "Password change is required before accessing this resource",
			},
		)
	}
}

func isPasswordChangeAllowedRoute(fullPath string) bool {
	// Gin returns the fully registered route, including the /api/v1 group. The
	// relative form is also accepted to keep this helper usable in isolated
	// middleware tests.
	path := strings.TrimSuffix(fullPath, "/")
	path = strings.TrimPrefix(path, "/api/v1")

	switch path {
	case "/change-password", "/auth/logout", "/auth/logout-all", "/profile":
		return true
	default:
		return false
	}
}
