package incidentanalytics

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
type generateRequest struct {
	Name string `json:"name" binding:"required,max=255"`
}
type archiveRequest struct {
	ID string `json:"id" binding:"required,uuid"`
}
type record struct {
	ID          uuid.UUID      `json:"id"`
	Name        string         `json:"name"`
	Status      string         `json:"status"`
	Metrics     map[string]any `json:"metrics"`
	GeneratedBy uuid.UUID      `json:"generated_by"`
	GeneratedAt time.Time      `json:"generated_at"`
	ArchivedBy  *uuid.UUID     `json:"archived_by,omitempty"`
	ArchivedAt  *time.Time     `json:"archived_at,omitempty"`
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.db = db
	g := p.Group("/incident-analytics")
	g.GET("", middleware.RequirePermission(db, "INCIDENT_ANALYTICS_VIEW"), h.ListAnalytics)
	g.GET("/:id", middleware.RequirePermission(db, "INCIDENT_ANALYTICS_VIEW"), h.GetAnalytics)
	g.POST("/generate", middleware.RequirePermission(db, "INCIDENT_ANALYTICS_GENERATE"), h.GenerateAnalytics)
	g.POST("/archive", middleware.RequirePermission(db, "INCIDENT_ANALYTICS_ARCHIVE"), h.ArchiveAnalytics)
}

const cols = `id,name,status,metrics,generated_by,generated_at,archived_by,archived_at`

type scanner interface{ Scan(...any) error }

func scan(s scanner) (record, error) {
	var v record
	e := s.Scan(&v.ID, &v.Name, &v.Status, &v.Metrics, &v.GeneratedBy, &v.GeneratedAt, &v.ArchivedBy, &v.ArchivedAt)
	return v, e
}
func (h *Handler) ListAnalytics(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, e := h.db.Query(c, `SELECT `+cols+` FROM incident_analytics_snapshots WHERE organization_id=$1 ORDER BY generated_at DESC LIMIT 200`, org)
	if e != nil {
		operational.Failure(c, 500, "Unable to list incident analytics")
		return
	}
	defer rows.Close()
	items := make([]record, 0)
	for rows.Next() {
		v, e := scan(rows)
		if e != nil {
			operational.Failure(c, 500, "Unable to read incident analytics")
			return
		}
		items = append(items, v)
	}
	c.JSON(200, gin.H{"success": true, "data": items})
}
func (h *Handler) GetAnalytics(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	id, e := uuid.Parse(c.Param("id"))
	if e != nil {
		operational.Failure(c, 400, "Invalid analytics ID")
		return
	}
	v, e := scan(h.db.QueryRow(c, `SELECT `+cols+` FROM incident_analytics_snapshots WHERE organization_id=$1 AND id=$2`, org, id))
	if e == pgx.ErrNoRows {
		operational.Failure(c, 404, "Incident analytics not found")
		return
	}
	if e != nil {
		operational.Failure(c, 500, "Unable to retrieve incident analytics")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": v})
}
func (h *Handler) GenerateAnalytics(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := operational.ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q generateRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid analytics request", "error": e.Error()})
		return
	}
	var metrics map[string]any
	e := h.db.QueryRow(c, `SELECT jsonb_build_object('total',count(*),'open',count(*) FILTER(WHERE status NOT IN('RESOLVED','CLOSED')),'critical',count(*) FILTER(WHERE severity='CRITICAL'),'resolved',count(*) FILTER(WHERE status='RESOLVED'),'closed',count(*) FILTER(WHERE status='CLOSED'),'evidence_preserved',count(*) FILTER(WHERE evidence_preserved=TRUE)) FROM incidents WHERE organization_id=$1 AND deleted_at IS NULL`, org).Scan(&metrics)
	if e != nil {
		operational.Failure(c, 500, "Incident metrics could not be calculated")
		return
	}
	v, e := scan(h.db.QueryRow(c, `INSERT INTO incident_analytics_snapshots(id,organization_id,name,metrics,generated_by) VALUES($1,$2,$3,$4,$5) RETURNING `+cols, uuid.New(), org, strings.TrimSpace(q.Name), metrics, actor))
	if e != nil {
		operational.Failure(c, 500, "Incident analytics could not be stored")
		return
	}
	c.JSON(201, gin.H{"success": true, "message": "Incident analytics generated", "data": v})
}
func (h *Handler) ArchiveAnalytics(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := operational.ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q archiveRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid archive request", "error": e.Error()})
		return
	}
	id, _ := uuid.Parse(q.ID)
	v, e := scan(h.db.QueryRow(c, `UPDATE incident_analytics_snapshots SET status='ARCHIVED',archived_by=$3,archived_at=NOW() WHERE organization_id=$1 AND id=$2 AND status='ACTIVE' RETURNING `+cols, org, id, actor))
	if e == pgx.ErrNoRows {
		operational.Failure(c, 409, "Analytics record is missing or already archived")
		return
	}
	if e != nil {
		operational.Failure(c, 500, "Analytics record could not be archived")
		return
	}
	c.JSON(200, gin.H{"success": true, "message": "Incident analytics archived", "data": v})
}
