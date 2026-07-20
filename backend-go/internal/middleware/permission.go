package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

var (
	errUserIDNotFound = errors.New("authenticated user ID not found")
	errInvalidUserID  = errors.New("authenticated user ID is invalid")
)

func RequirePermission(
	db *pgxpool.Pool,
	requiredPermission string,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := getAuthenticatedUserID(c)
		if err != nil {
			response.Error(
				c,
				http.StatusUnauthorized,
				"Authentication information is invalid",
				err.Error(),
			)

			c.Abort()
			return
		}

		requiredPermission = strings.TrimSpace(
			strings.ToUpper(requiredPermission),
		)

		if requiredPermission == "" {
			response.Error(
				c,
				http.StatusInternalServerError,
				"Required permission is not configured",
				nil,
			)

			c.Abort()
			return
		}

		hasAccess, err := userHasPermission(
			c,
			db,
			userID,
			requiredPermission,
		)
		if err != nil {
			response.Error(
				c,
				http.StatusInternalServerError,
				"Failed to verify user permission",
				err.Error(),
			)

			c.Abort()
			return
		}

		if !hasAccess {
			response.Error(
				c,
				http.StatusForbidden,
				"You do not have permission to access this resource",
				nil,
			)

			c.Abort()
			return
		}

		c.Next()
	}
}

func getAuthenticatedUserID(
	c *gin.Context,
) (uuid.UUID, error) {
	value, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, errUserIDNotFound
	}

	switch userID := value.(type) {
	case uuid.UUID:
		if userID == uuid.Nil {
			return uuid.Nil, errInvalidUserID
		}

		return userID, nil

	case string:
		parsedUserID, err := uuid.Parse(
			strings.TrimSpace(userID),
		)
		if err != nil {
			return uuid.Nil, errInvalidUserID
		}

		return parsedUserID, nil

	default:
		return uuid.Nil, errInvalidUserID
	}
}

func userHasPermission(
	c *gin.Context,
	db *pgxpool.Pool,
	userID uuid.UUID,
	requiredPermission string,
) (bool, error) {
	const query = `
	SELECT EXISTS (
		SELECT 1
		FROM user_roles AS ur
		INNER JOIN roles AS r
			ON r.id = ur.role_id
		LEFT JOIN role_permissions AS rp
			ON rp.role_id = r.id
			AND rp.is_active = TRUE
			AND (
				rp.expires_at IS NULL
				OR rp.expires_at > CURRENT_TIMESTAMP
			)
		LEFT JOIN permissions AS p
			ON p.id = rp.permission_id
			AND UPPER(p.status) = 'ACTIVE'
		WHERE ur.user_id = $1
			AND ur.is_active = TRUE
			AND UPPER(ur.status) = 'ACTIVE'
			AND ur.valid_from <= CURRENT_TIMESTAMP
			AND (
				ur.expires_at IS NULL
				OR ur.expires_at > CURRENT_TIMESTAMP
			)
			AND (
				UPPER(r.role_code) = 'SUPER_ADMIN'
				OR UPPER(p.permission_code) = $2
			)
	)
`

	var hasAccess bool

	err := db.QueryRow(
		c.Request.Context(),
		query,
		userID,
		requiredPermission,
	).Scan(&hasAccess)
	if err != nil {
		return false, err
	}

	return hasAccess, nil
}
