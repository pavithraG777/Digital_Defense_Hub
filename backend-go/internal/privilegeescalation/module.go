package privilegeescalation

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

type Handler struct {
	repo    *Repository
	service *Service
}

func NewHandler() *Handler {
	return &Handler{}
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}

	// wire repository and detection service
	if handler.repo == nil {
		if repo, err := NewRepository(databasePool); err == nil {
			_ = repo.EnsureSchema(context.Background())
			handler.repo = repo
			handler.service = NewService(repo)
		}
	}

	group := protected.Group("/privilegeescalation")
	group.GET("/detections", middleware.RequirePermission(databasePool, "PRIVILEGE_ESCALATION_VIEW"), handler.ListDetections)
	group.POST("/verify", middleware.RequirePermission(databasePool, "PRIVILEGE_ESCALATION_MANAGE"), handler.Verify)
	group.PATCH("/detections/:id/status", middleware.RequirePermission(databasePool, "PRIVILEGE_ESCALATION_MANAGE"), handler.UpdateStatus)
}

func (h *Handler) ListDetections(c *gin.Context) {
	orgID, ok := privilegeContextID(c, "organization_id")
	if ok && h.repo != nil {
		detections, err := h.repo.ListDetections(c.Request.Context(), orgID, 50, 0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "detections": detections})
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid organization context"})
}

func (h *Handler) Verify(c *gin.Context) {
	var payload map[string]any
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	detectionType, score := h.service.AnalyzeEvent(c.Request.Context(), payload)
	orgID, ok := privilegeContextID(c, "organization_id")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid organization context"})
		return
	}

	// if high confidence, persist
	if score >= 0.8 && h.repo != nil {
		host := ""
		if hst, ok := payload["host"].(string); ok {
			host = hst
		}
		userID := uuid.Nil
		if ustr, ok := payload["user_id"].(string); ok {
			if uid, err := uuid.Parse(ustr); err == nil {
				userID = uid
			}
		}

		// build metadata
		metadata := map[string]any{"raw": payload}

		d := &Detection{
			OrganizationID: orgID,
			Host:           host,
			UserID:         userID,
			DetectionType:  detectionType,
			Metadata:       metadata,
			CreatedAt:      time.Now().UTC(),
		}
		created, err := h.repo.CreateDetection(c.Request.Context(), d)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"success": true, "detection_type": detectionType, "confidence": score, "detection": created})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "detection_type": detectionType, "confidence": score})
}

func privilegeContextID(c *gin.Context, key string) (uuid.UUID, bool) {
	v, ok := c.Get(key)
	if !ok {
		return uuid.Nil, false
	}
	switch id := v.(type) {
	case uuid.UUID:
		return id, id != uuid.Nil
	case string:
		parsed, err := uuid.Parse(id)
		return parsed, err == nil && parsed != uuid.Nil
	}
	return uuid.Nil, false
}

func (h *Handler) UpdateStatus(c *gin.Context) {
	orgID, ok := privilegeContextID(c, "organization_id")
	actor, _ := privilegeContextID(c, "user_id")
	id, err := uuid.Parse(c.Param("id"))
	if !ok || err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid context"})
		return
	}
	var q struct {
		Status string `json:"status" binding:"required,oneof=OPEN INVESTIGATING CONFIRMED FALSE_POSITIVE RESOLVED"`
		Note   string `json:"note" binding:"required"`
	}
	if err = c.ShouldBindJSON(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	tag, err := h.repo.db.Exec(c, `UPDATE privilege_escalation_detections SET status=$3,review_note=$4,reviewed_by=$5,reviewed_at=NOW() WHERE organization_id=$1 AND id=$2`, orgID, id, q.Status, q.Note, actor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	if tag.RowsAffected() != 1 {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "detection not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "id": id, "status": q.Status})
}
