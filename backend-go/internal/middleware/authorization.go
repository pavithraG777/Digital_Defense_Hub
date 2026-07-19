package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

func RequireRoles(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {

		value, exists := c.Get("roles")
		if !exists {
			response.Error(
				c,
				http.StatusForbidden,
				"Roles not found",
				nil,
			)
			c.Abort()
			return
		}

		userRoles, ok := value.([]string)
		if !ok {
			response.Error(
				c,
				http.StatusForbidden,
				"Invalid role information",
				nil,
			)
			c.Abort()
			return
		}

		for _, userRole := range userRoles {

			for _, allowedRole := range allowedRoles {

				if userRole == allowedRole {
					c.Next()
					return
				}

			}
		}

		response.Error(
			c,
			http.StatusForbidden,
			"You are not authorized to access this resource",
			nil,
		)

		c.Abort()
	}
}
