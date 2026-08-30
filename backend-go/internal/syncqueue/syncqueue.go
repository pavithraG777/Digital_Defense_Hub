// Package syncqueue implements an organization-scoped outbox for offline
// clients. It transports metadata only; files and case material remain subject
// to their existing authorization and evidence controls.
package syncqueue

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type enqueueRequest struct {
	SyncType string          `json:"sync_type" binding:"required,oneof=PENDING_DATA THREAT_INTELLIGENCE AI_MODEL CASE_TRANSFER BACKUP"`
	Payload  json.RawMessage `json:"payload" binding:"required"`
	Checksum string          `json:"checksum_sha256" binding:"omitempty,len=64,hexadecimal"`
}

func RegisterRoutes(group *gin.RouterGroup, db *pgxpool.Pool) {
	queue := group.Group("/offline-sync")
	queue.POST("/queue", middleware.RequirePermission(db, "ORGANIZATION_MANAGE_SECURITY"), func(c *gin.Context) {
		var request enqueueRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			response.BadRequest(c, "Invalid sync request", err.Error())
			return
		}
		if !json.Valid(request.Payload) {
			response.BadRequest(c, "Sync payload must be valid JSON", nil)
			return
		}
		organizationID, ok := contextUUID(c, "organization_id")
		if !ok {
			response.Unauthorized(c, "Organization authentication context is invalid", nil)
			return
		}
		userID, _ := contextUUID(c, "user_id")
		computed := fmt.Sprintf("%x", sha256.Sum256(request.Payload))
		if request.Checksum != "" && !strings.EqualFold(request.Checksum, computed) {
			response.BadRequest(c, "Sync checksum does not match payload", nil)
			return
		}
		var id uuid.UUID
		err := db.QueryRow(c.Request.Context(), `INSERT INTO offline_sync_queue (organization_id,sync_type,payload,checksum_sha256,created_by) VALUES ($1,$2,$3,$4,$5) RETURNING id`, organizationID, strings.ToUpper(request.SyncType), request.Payload, computed, nullableUUID(userID)).Scan(&id)
		if err != nil {
			response.InternalServerError(c, "Failed to queue offline sync", err.Error())
			return
		}
		response.Success(c, http.StatusCreated, "Offline sync queued", gin.H{"sync_id": id, "status": "PENDING"})
	})
	queue.GET("/queue", middleware.RequirePermission(db, "ORGANIZATION_MANAGE_SECURITY"), func(c *gin.Context) {
		organizationID, ok := contextUUID(c, "organization_id")
		if !ok {
			response.Unauthorized(c, "Organization authentication context is invalid", nil)
			return
		}
		rows, err := db.Query(c.Request.Context(), `SELECT id,sync_type,status,retry_count,last_error,created_at,claimed_at,completed_at FROM offline_sync_queue WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100`, organizationID)
		if err != nil {
			response.InternalServerError(c, "Failed to retrieve offline sync queue", err.Error())
			return
		}
		defer rows.Close()
		items := make([]gin.H, 0)
		for rows.Next() {
			var id uuid.UUID
			var kind, status string
			var retries int
			var lastError *string
			var createdAt, claimedAt, completedAt any
			if err := rows.Scan(&id, &kind, &status, &retries, &lastError, &createdAt, &claimedAt, &completedAt); err != nil {
				response.InternalServerError(c, "Failed to read offline sync queue", err.Error())
				return
			}
			items = append(items, gin.H{"id": id, "sync_type": kind, "status": status, "retry_count": retries, "last_error": lastError, "created_at": createdAt, "claimed_at": claimedAt, "completed_at": completedAt})
		}
		response.Success(c, http.StatusOK, "Offline sync queue retrieved", items)
	})
	queue.POST("/queue/:id/claim", middleware.RequirePermission(db, "SYNC_EXECUTE"), transitionHandler(db, "IN_PROGRESS"))
	queue.POST("/queue/:id/complete", middleware.RequirePermission(db, "SYNC_EXECUTE"), completeHandler(db))
	queue.POST("/queue/:id/retry", middleware.RequirePermission(db, "SYNC_RETRY"), transitionHandler(db, "PENDING"))
	queue.POST("/queue/:id/cancel", middleware.RequirePermission(db, "SYNC_CANCEL"), transitionHandler(db, "CANCELLED"))
}

func transitionHandler(db *pgxpool.Pool, target string) gin.HandlerFunc {
	return func(c *gin.Context) {
		org, ok := contextUUID(c, "organization_id")
		id, err := uuid.Parse(c.Param("id"))
		if !ok || err != nil {
			response.BadRequest(c, "Invalid sync context", nil)
			return
		}
		allowed := map[string][]string{"IN_PROGRESS": {"PENDING"}, "PENDING": {"FAILED"}, "CANCELLED": {"PENDING", "FAILED"}}[target]
		tag, err := db.Exec(c, `UPDATE offline_sync_queue SET status=$3,retry_count=retry_count+CASE WHEN $3='PENDING' THEN 1 ELSE 0 END,last_error=CASE WHEN $3='PENDING' THEN NULL ELSE last_error END,claimed_at=CASE WHEN $3='IN_PROGRESS' THEN NOW() ELSE claimed_at END,updated_at=NOW() WHERE organization_id=$1 AND id=$2 AND status=ANY($4)`, org, id, target, allowed)
		if err != nil {
			response.InternalServerError(c, "Could not update sync item", err.Error())
			return
		}
		if tag.RowsAffected() != 1 {
			response.Error(c, http.StatusConflict, "Sync transition is not allowed", nil)
			return
		}
		response.OK(c, "Sync queue state updated", gin.H{"id": id, "status": target})
	}
}
func completeHandler(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		org, ok := contextUUID(c, "organization_id")
		id, err := uuid.Parse(c.Param("id"))
		if !ok || err != nil {
			response.BadRequest(c, "Invalid sync context", nil)
			return
		}
		var q struct {
			Checksum string `json:"checksum_sha256" binding:"required,len=64,hexadecimal"`
		}
		if err = c.ShouldBindJSON(&q); err != nil {
			response.BadRequest(c, "Completion checksum is required", err.Error())
			return
		}
		tag, err := db.Exec(c, `UPDATE offline_sync_queue SET status='COMPLETED',completed_at=NOW(),updated_at=NOW() WHERE organization_id=$1 AND id=$2 AND status='IN_PROGRESS' AND checksum_sha256=$3`, org, id, strings.ToLower(q.Checksum))
		if err != nil {
			response.InternalServerError(c, "Could not complete sync item", err.Error())
			return
		}
		if tag.RowsAffected() != 1 {
			response.Error(c, http.StatusConflict, "Sync item is not in progress or checksum differs", nil)
			return
		}
		response.OK(c, "Sync item completed", gin.H{"id": id, "status": "COMPLETED"})
	}
}

func contextUUID(c *gin.Context, key string) (uuid.UUID, bool) {
	value, exists := c.Get(key)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := value.(uuid.UUID)
	return id, ok && id != uuid.Nil
}
func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
