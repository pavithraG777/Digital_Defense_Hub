package honeytoken

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// requestIncludesPlatformOwnedData is deliberately derived from the signed
// access-token roles. Tenant administrators must never inherit records created
// by a platform SUPER_ADMIN even when legacy rows carry the tenant's org ID.
func requestIncludesPlatformOwnedData(c *gin.Context) bool {
	if c == nil {
		return false
	}
	value, ok := c.Get("roles")
	if !ok {
		return false
	}
	roles, ok := value.([]string)
	if !ok {
		return false
	}
	for _, role := range roles {
		if strings.EqualFold(strings.TrimSpace(role), "SUPER_ADMIN") {
			return true
		}
	}
	return false
}

func requestIncludesTenantAdminOwnedData(c *gin.Context) bool {
	if requestIncludesPlatformOwnedData(c) {
		return true
	}
	value, ok := c.Get("roles")
	if !ok {
		return false
	}
	roles, ok := value.([]string)
	if !ok {
		return false
	}
	for _, role := range roles {
		role = strings.ToUpper(strings.TrimSpace(role))
		if role == "MANAGER" || role == "ORG_ADMIN" || role == "ORGANIZATION_ADMIN" || strings.Contains(role, "ADMIN") {
			return true
		}
	}
	return false
}
