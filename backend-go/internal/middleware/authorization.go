package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RequireRoles(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {

		value, exists := c.Get("roles")
		if !exists {
			abortWithError(c, http.StatusForbidden, "Roles not found", nil)
			return
		}

		userRoles, ok := value.([]string)
		if !ok {
			abortWithError(c, http.StatusForbidden, "Invalid role information", nil)
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

		abortWithError(c, http.StatusForbidden, "You are not authorized to access this resource", nil)
	}
}
