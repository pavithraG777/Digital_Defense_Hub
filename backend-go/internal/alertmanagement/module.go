package alertmanagement

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"strings"
	"time"
)

type Handler struct{ db *pgxpool.Pool }
type createRequest struct {
	AlertCode   string         `json:"alert_code" binding:"required,max=100"`
	Title       string         `json:"title" binding:"required,max=255"`
	Description string         `json:"description" binding:"omitempty,max=4000"`
	Source      string         `json:"source" binding:"required,max=100"`
	Severity    string         `json:"severity" binding:"required,oneof=LOW MEDIUM HIGH CRITICAL"`
	Payload     map[string]any `json:"payload"`
}
type actionRequest struct {
	ID     string `json:"id" binding:"required,uuid"`
	Reason string `json:"reason" binding:"omitempty,max=1000"`
}
type record struct {
	ID                uuid.UUID      `json:"id"`
	AlertCode         string         `json:"alert_code"`
	Title             string         `json:"title"`
	Description       *string        `json:"description,omitempty"`
	Source            string         `json:"source"`
	Severity          string         `json:"severity"`
	Status            string         `json:"status"`
	Payload           map[string]any `json:"payload"`
	AcknowledgedBy    *uuid.UUID     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt    *time.Time     `json:"acknowledged_at,omitempty"`
	SuppressedBy      *uuid.UUID     `json:"suppressed_by,omitempty"`
	SuppressedAt      *time.Time     `json:"suppressed_at,omitempty"`
	SuppressionReason *string        `json:"suppression_reason,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.db = db
	g := p.Group("/alert-management")
	g.GET("", middleware.RequirePermission(db, "ALERT_MANAGEMENT_VIEW"), h.ListAlerts)
	g.GET("/:id", middleware.RequirePermission(db, "ALERT_MANAGEMENT_VIEW"), h.GetAlert)
	g.POST("", middleware.RequirePermission(db, "ALERT_MANAGEMENT_ACKNOWLEDGE"), h.CreateAlert)
	g.POST("/acknowledge", middleware.RequirePermission(db, "ALERT_MANAGEMENT_ACKNOWLEDGE"), h.AcknowledgeAlert)
	g.POST("/suppress", middleware.RequirePermission(db, "ALERT_MANAGEMENT_SUPPRESS"), h.SuppressAlert)
}
func (h *Handler) ListAlerts(c *gin.Context) {
	org, ok := ctxID(c, "organization_id")
	if !ok {
		return
	}
	rows, e := h.db.Query(c, selectSQL+` WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 500`, org)
	if e != nil {
		fail(c, 500, "Unable to list alerts")
		return
	}
	defer rows.Close()
	items := make([]record, 0)
	for rows.Next() {
		v, e := scan(rows)
		if e != nil {
			fail(c, 500, "Unable to read alerts")
			return
		}
		items = append(items, v)
	}
	if rows.Err() != nil {
		fail(c, 500, "Unable to list alerts")
		return
	}
	c.JSON(200, gin.H{"success": true, "message": "Alerts retrieved successfully", "data": items})
}
func (h *Handler) GetAlert(c *gin.Context) {
	org, ok := ctxID(c, "organization_id")
	if !ok {
		return
	}
	id, e := uuid.Parse(c.Param("id"))
	if e != nil {
		fail(c, 400, "Invalid alert ID")
		return
	}
	v, e := scan(h.db.QueryRow(c, selectSQL+` WHERE organization_id=$1 AND id=$2`, org, id))
	if e == pgx.ErrNoRows {
		fail(c, 404, "Alert not found")
		return
	}
	if e != nil {
		fail(c, 500, "Unable to retrieve alert")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": v})
}
func (h *Handler) CreateAlert(c *gin.Context) {
	org, ok := ctxID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := ctxID(c, "user_id")
	if !ok {
		return
	}
	var q createRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid alert payload", "error": e.Error()})
		return
	}
	q.AlertCode = strings.TrimSpace(q.AlertCode)
	q.Title = strings.TrimSpace(q.Title)
	q.Source = strings.TrimSpace(q.Source)
	q.Severity = strings.ToUpper(q.Severity)
	v, e := scan(h.db.QueryRow(c, `INSERT INTO security_alert_records(id,organization_id,alert_code,title,description,source,severity,payload,created_by) VALUES($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,$9) RETURNING `+columns, uuid.New(), org, q.AlertCode, q.Title, strings.TrimSpace(q.Description), q.Source, q.Severity, q.Payload, actor))
	if e != nil {
		c.JSON(409, gin.H{"success": false, "message": "Alert could not be created", "error": e.Error()})
		return
	}
	c.JSON(201, gin.H{"success": true, "message": "Alert created successfully", "data": v})
}
func (h *Handler) AcknowledgeAlert(c *gin.Context) { h.transition(c, "ACKNOWLEDGED") }
func (h *Handler) SuppressAlert(c *gin.Context)    { h.transition(c, "SUPPRESSED") }
func (h *Handler) transition(c *gin.Context, status string) {
	org, ok := ctxID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := ctxID(c, "user_id")
	if !ok {
		return
	}
	var q actionRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid alert action", "error": e.Error()})
		return
	}
	id, _ := uuid.Parse(q.ID)
	var row pgx.Row
	if status == "ACKNOWLEDGED" {
		row = h.db.QueryRow(c, `UPDATE security_alert_records SET status='ACKNOWLEDGED',acknowledged_by=$3,acknowledged_at=NOW(),updated_at=NOW() WHERE organization_id=$1 AND id=$2 AND status='OPEN' RETURNING `+columns, org, id, actor)
	} else {
		if strings.TrimSpace(q.Reason) == "" {
			fail(c, 400, "Suppression reason is required")
			return
		}
		row = h.db.QueryRow(c, `UPDATE security_alert_records SET status='SUPPRESSED',suppressed_by=$3,suppressed_at=NOW(),suppression_reason=$4,updated_at=NOW() WHERE organization_id=$1 AND id=$2 AND status IN('OPEN','ACKNOWLEDGED') RETURNING `+columns, org, id, actor, strings.TrimSpace(q.Reason))
	}
	v, e := scan(row)
	if e == pgx.ErrNoRows {
		fail(c, 409, "Alert transition is not allowed")
		return
	}
	if e != nil {
		fail(c, 500, "Alert could not be updated")
		return
	}
	c.JSON(200, gin.H{"success": true, "message": "Alert status updated successfully", "data": v})
}

const columns = `id,alert_code,title,description,source,severity,status,payload,acknowledged_by,acknowledged_at,suppressed_by,suppressed_at,suppression_reason,created_at,updated_at`
const selectSQL = `SELECT ` + columns + ` FROM security_alert_records`

type scanner interface{ Scan(...any) error }

func scan(s scanner) (record, error) {
	var v record
	e := s.Scan(&v.ID, &v.AlertCode, &v.Title, &v.Description, &v.Source, &v.Severity, &v.Status, &v.Payload, &v.AcknowledgedBy, &v.AcknowledgedAt, &v.SuppressedBy, &v.SuppressedAt, &v.SuppressionReason, &v.CreatedAt, &v.UpdatedAt)
	return v, e
}
func ctxID(c *gin.Context, key string) (uuid.UUID, bool) {
	v, x := c.Get(key)
	if !x {
		fail(c, 401, "Authentication context is missing")
		return uuid.Nil, false
	}
	if id, x := v.(uuid.UUID); x && id != uuid.Nil {
		return id, true
	}
	if s, x := v.(string); x {
		if id, e := uuid.Parse(s); e == nil {
			return id, true
		}
	}
	fail(c, 401, "Authentication context is invalid")
	return uuid.Nil, false
}
func fail(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"success": false, "message": message})
}
