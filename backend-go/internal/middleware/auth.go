package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

const (
	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "
)

func Authenticate(jwtManager *auth.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorizationHeader := strings.TrimSpace(
			c.GetHeader(AuthorizationHeader),
		)

		if authorizationHeader == "" {
			response.Error(
				c,
				http.StatusUnauthorized,
				"Authorization header is required",
				nil,
			)
			c.Abort()
			return
		}

		if !strings.HasPrefix(
			authorizationHeader,
			BearerPrefix,
		) {
			response.Error(
				c,
				http.StatusUnauthorized,
				"Authorization header must use Bearer token",
				nil,
			)
			c.Abort()
			return
		}

		tokenString := strings.TrimSpace(
			strings.TrimPrefix(
				authorizationHeader,
				BearerPrefix,
			),
		)

		if tokenString == "" {
			response.Error(
				c,
				http.StatusUnauthorized,
				"Access token is required",
				nil,
			)
			c.Abort()
			return
		}

		claims, err := jwtManager.ValidateAccessToken(tokenString)
		if err != nil {
			fmt.Println("JWT validation error:", err)

			response.Error(
				c,
				http.StatusUnauthorized,
				"Invalid or expired access token",
				err.Error(),
			)

			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("organization_id", claims.OrganizationID)
		c.Set("username", claims.Username)
		c.Set("roles", claims.Roles)
		c.Set("token_id", claims.ID)

		c.Next()
	}
}
