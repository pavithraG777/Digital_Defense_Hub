package accesscontrol

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
	"strings"
	"time"
)

type Handler struct{ db *pgxpool.Pool }
type grantRequest struct {
	SubjectType   string `json:"subject_type" binding:"required,oneof=USER ROLE SERVICE"`
	SubjectID     string `json:"subject_id" binding:"required,max=255"`
	ResourceType  string `json:"resource_type" binding:"required,max=80"`
	ResourceID    string `json:"resource_id" binding:"required,max=255"`
	Permission    string `json:"permission" binding:"required,max=150"`
	Justification string `json:"justification" binding:"required,max=1000"`
}
type revokeRequest struct {
	ID     string `json:"id" binding:"required,uuid"`
	Reason string `json:"reason" binding:"required,max=1000"`
}
type record struct {
	ID            uuid.UUID  `json:"id"`
	SubjectType   string     `json:"subject_type"`
	SubjectID     string     `json:"subject_id"`
	ResourceType  string     `json:"resource_type"`
	ResourceID    string     `json:"resource_id"`
	Permission    string     `json:"permission"`
	Status        string     `json:"status"`
	Justification string     `json:"justification"`
	RequestedBy   uuid.UUID  `json:"requested_by"`
	GrantedBy     *uuid.UUID `json:"granted_by,omitempty"`
	GrantedAt     *time.Time `json:"granted_at,omitempty"`
	RevokedBy     *uuid.UUID `json:"revoked_by,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokeReason  *string    `json:"revoke_reason,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.db = db
	g := p.Group("/access-control")
	g.GET("", middleware.RequirePermission(db, "ACCESS_CONTROL_VIEW"), h.ListAccessControls)
	g.GET("/:id", middleware.RequirePermission(db, "ACCESS_CONTROL_VIEW"), h.GetAccessControl)
	g.POST("/grant", middleware.RequirePermission(db, "ACCESS_CONTROL_MODIFY"), h.GrantAccess)
	g.POST("/revoke", middleware.RequirePermission(db, "ACCESS_CONTROL_MODIFY"), h.RevokeAccess)
}
func (h *Handler) ListAccessControls(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, e := h.db.Query(c, selectSQL+` WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 500`, org)
	if e != nil {
		operational.Failure(c, 500, "Unable to list access operations")
		return
	}
	defer rows.Close()
	items := make([]record, 0)
	for rows.Next() {
		v, e := scan(rows)
		if e != nil {
			operational.Failure(c, 500, "Unable to read access operations")
			return
		}
		items = append(items, v)
	}
	if rows.Err() != nil {
		operational.Failure(c, 500, "Unable to list access operations")
		return
	}
	c.JSON(200, gin.H{"success": true, "message": "Access operations retrieved successfully", "data": items})
}
func (h *Handler) GetAccessControl(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	id, e := uuid.Parse(c.Param("id"))
	if e != nil {
		operational.Failure(c, 400, "Invalid access operation ID")
		return
	}
	v, e := scan(h.db.QueryRow(c, selectSQL+` WHERE organization_id=$1 AND id=$2`, org, id))
	if e == pgx.ErrNoRows {
		operational.Failure(c, 404, "Access operation not found")
		return
	}
	if e != nil {
		operational.Failure(c, 500, "Unable to retrieve access operation")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": v})
}
func (h *Handler) GrantAccess(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := operational.ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q grantRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid access grant payload", "error": e.Error()})
		return
	}
	q.SubjectType = strings.ToUpper(q.SubjectType)
	q.ResourceType = strings.ToUpper(strings.TrimSpace(q.ResourceType))
	q.Permission = strings.ToUpper(strings.TrimSpace(q.Permission))
	v, e := scan(h.db.QueryRow(c, `INSERT INTO access_control_operations(id,organization_id,subject_type,subject_id,resource_type,resource_id,permission,status,justification,requested_by,granted_by,granted_at) VALUES($1,$2,$3,$4,$5,$6,$7,'ACTIVE',$8,$9,$9,NOW()) RETURNING `+columns, uuid.New(), org, q.SubjectType, strings.TrimSpace(q.SubjectID), q.ResourceType, strings.TrimSpace(q.ResourceID), q.Permission, strings.TrimSpace(q.Justification), actor))
	if e != nil {
		operational.Failure(c, 500, "Access grant could not be recorded")
		return
	}
	c.JSON(201, gin.H{"success": true, "message": "Access granted and audited", "data": v})
}
func (h *Handler) RevokeAccess(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := operational.ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q revokeRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid access revoke payload", "error": e.Error()})
		return
	}
	id, _ := uuid.Parse(q.ID)
	v, e := scan(h.db.QueryRow(c, `UPDATE access_control_operations SET status='REVOKED',revoked_by=$3,revoked_at=NOW(),revoke_reason=$4,updated_at=NOW() WHERE organization_id=$1 AND id=$2 AND status='ACTIVE' RETURNING `+columns, org, id, actor, strings.TrimSpace(q.Reason)))
	if e == pgx.ErrNoRows {
		operational.Failure(c, 409, "Access grant is missing or already revoked")
		return
	}
	if e != nil {
		operational.Failure(c, 500, "Access revoke could not be recorded")
		return
	}
	c.JSON(200, gin.H{"success": true, "message": "Access revoked and audited", "data": v})
}

const columns = `id,subject_type,subject_id,resource_type,resource_id,permission,status,justification,requested_by,granted_by,granted_at,revoked_by,revoked_at,revoke_reason,created_at,updated_at`
const selectSQL = `SELECT ` + columns + ` FROM access_control_operations`

type scanner interface{ Scan(...any) error }

func scan(s scanner) (record, error) {
	var v record
	e := s.Scan(&v.ID, &v.SubjectType, &v.SubjectID, &v.ResourceType, &v.ResourceID, &v.Permission, &v.Status, &v.Justification, &v.RequestedBy, &v.GrantedBy, &v.GrantedAt, &v.RevokedBy, &v.RevokedAt, &v.RevokeReason, &v.CreatedAt, &v.UpdatedAt)
	return v, e
}
