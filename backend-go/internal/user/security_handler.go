package user

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RegisterSecurityRoutes exposes tenant-scoped account-security metadata to
// authorized IAM operators. It intentionally never returns credentials,
// session token hashes, MFA secrets, or recovery material.
func RegisterSecurityRoutes(admin *gin.RouterGroup, db *pgxpool.Pool, require func(string) gin.HandlerFunc) {
	admin.GET("/users/:id/security", require("USER_VIEW_DETAILS"), userSecuritySummary(db))
	admin.GET("/users/:id/devices", require("USER_VIEW_DETAILS"), userDevices(db))
	admin.GET("/users/:id/sessions", require("USER_VIEW_DETAILS"), userSessions(db))
}

func securityTarget(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	org, ok := getUUIDFromContext(c, "organization_id")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Organization information is missing"})
		return uuid.Nil, uuid.Nil, false
	}
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil || userID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid user ID"})
		return uuid.Nil, uuid.Nil, false
	}
	return org, userID, true
}

func userSecuritySummary(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		org, userID, ok := securityTarget(c)
		if !ok {
			return
		}
		var mfa bool
		var status string
		var devices, sessions int
		err := db.QueryRow(c, `SELECT u.mfa_enabled,u.account_status,(SELECT count(*) FROM authentication_trusted_devices d WHERE d.user_id=u.id AND d.organization_id=u.organization_id AND d.revoked_at IS NULL),(SELECT count(*) FROM authentication_sessions s WHERE s.user_id=u.id AND s.organization_id=u.organization_id AND s.status='ACTIVE' AND s.expires_at>NOW()) FROM users u WHERE u.id=$1 AND u.organization_id=$2`, userID, org).Scan(&mfa, &status, &devices, &sessions)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "User not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"mfa_enabled": mfa, "account_status": status, "trusted_device_count": devices, "active_session_count": sessions}})
	}
}

func userDevices(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		org, userID, ok := securityTarget(c)
		if !ok {
			return
		}
		rows, err := db.Query(c, `SELECT id,device_id,device_name,trusted,last_seen_at,trusted_at FROM authentication_trusted_devices WHERE user_id=$1 AND organization_id=$2 AND revoked_at IS NULL ORDER BY last_seen_at DESC`, userID, org)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Unable to load trusted devices"})
			return
		}
		defer rows.Close()
		items := []gin.H{}
		for rows.Next() {
			var id uuid.UUID
			var deviceID, name string
			var trusted bool
			var seen any
			var trustedAt any
			if rows.Scan(&id, &deviceID, &name, &trusted, &seen, &trustedAt) == nil {
				items = append(items, gin.H{"id": id, "device_id": deviceID, "device_name": name, "trusted": trusted, "last_seen_at": seen, "trusted_at": trustedAt})
			}
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"items": items, "total": len(items)}})
	}
}

func userSessions(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		org, userID, ok := securityTarget(c)
		if !ok {
			return
		}
		rows, err := db.Query(c, `SELECT id,status,mfa_verified,login_at,last_activity_at,expires_at FROM authentication_sessions WHERE user_id=$1 AND organization_id=$2 ORDER BY last_activity_at DESC`, userID, org)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Unable to load sessions"})
			return
		}
		defer rows.Close()
		items := []gin.H{}
		for rows.Next() {
			var id uuid.UUID
			var status string
			var mfa bool
			var login, active, expires any
			if rows.Scan(&id, &status, &mfa, &login, &active, &expires) == nil {
				items = append(items, gin.H{"id": id, "status": status, "mfa_verified": mfa, "login_at": login, "last_activity_at": active, "expires_at": expires})
			}
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"items": items, "total": len(items)}})
	}
}
