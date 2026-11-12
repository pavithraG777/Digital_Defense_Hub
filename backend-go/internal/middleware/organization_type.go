package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RequireOrganizationTypeOrSuperAdmin prevents permissions intended for one
// industry from accidentally exposing restricted workflows to every tenant.
func RequireOrganizationTypeOrSuperAdmin(db *pgxpool.Pool, allowed ...string) gin.HandlerFunc {
	allowedTypes := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		allowedTypes[strings.ToUpper(strings.TrimSpace(value))] = struct{}{}
	}
	return func(c *gin.Context) {
		if roles, ok := c.Get("roles"); ok {
			if values, valid := roles.([]string); valid {
				for _, role := range values {
					if strings.EqualFold(strings.TrimSpace(role), "SUPER_ADMIN") {
						c.Next()
						return
					}
				}
			}
		}
		value, exists := c.Get("organization_id")
		if !exists {
			abortWithError(c, http.StatusUnauthorized, "Organization information is missing", nil)
			return
		}
		var organizationID uuid.UUID
		switch typed := value.(type) {
		case uuid.UUID:
			organizationID = typed
		case string:
			parsed, err := uuid.Parse(strings.TrimSpace(typed))
			if err == nil {
				organizationID = parsed
			}
		}
		if organizationID == uuid.Nil {
			abortWithError(c, http.StatusUnauthorized, "Organization information is invalid", nil)
			return
		}
		var organizationType string
		if err := db.QueryRow(c.Request.Context(), `SELECT UPPER(organization_type) FROM organizations WHERE id=$1 AND deleted_at IS NULL`, organizationID).Scan(&organizationType); err != nil {
			abortWithError(c, http.StatusForbidden, "Organization is not authorized for this workflow", nil)
			return
		}
		if _, ok := allowedTypes[organizationType]; !ok {
			abortWithError(c, http.StatusForbidden, "Investigation workspaces are restricted to authorized investigative organizations", nil)
			return
		}
		c.Next()
	}
}
