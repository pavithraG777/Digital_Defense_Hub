package compliance

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
	"strings"
	"time"
)

type Handler struct{ db *pgxpool.Pool }
type check struct {
	Control  string `json:"control" binding:"required"`
	Status   string `json:"status" binding:"required,oneof=PASS FAIL"`
	Evidence string `json:"evidence" binding:"required"`
}
type request struct {
	Framework string         `json:"framework" binding:"required,max=100"`
	Scope     string         `json:"scope" binding:"required,max=500"`
	Checks    []check        `json:"checks" binding:"required,min=1,dive"`
	Evidence  map[string]any `json:"evidence"`
}
type record struct {
	ID           uuid.UUID      `json:"id"`
	Framework    string         `json:"framework"`
	Scope        string         `json:"scope"`
	Status       string         `json:"status"`
	Score        float64        `json:"score"`
	PassedChecks int            `json:"passed_checks"`
	FailedChecks int            `json:"failed_checks"`
	Checks       []check        `json:"checks"`
	Evidence     map[string]any `json:"evidence"`
	ExecutedBy   uuid.UUID      `json:"executed_by"`
	ExecutedAt   time.Time      `json:"executed_at"`
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.db = db
	g := p.Group("/compliance")
	g.GET("/checks", middleware.RequirePermission(db, "COMPLIANCE_VIEW"), h.ListChecks)
	g.POST("/audits", middleware.RequirePermission(db, "COMPLIANCE_EXECUTE"), h.RunAudit)
}
func (h *Handler) ListChecks(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, e := h.db.Query(c, `SELECT id,framework,scope,status,score,passed_checks,failed_checks,checks,evidence,executed_by,executed_at FROM compliance_audits WHERE organization_id=$1 ORDER BY executed_at DESC LIMIT 200`, org)
	if e != nil {
		operational.Failure(c, 500, "Unable to list compliance audits")
		return
	}
	defer rows.Close()
	items := make([]record, 0)
	for rows.Next() {
		var v record
		if e = rows.Scan(&v.ID, &v.Framework, &v.Scope, &v.Status, &v.Score, &v.PassedChecks, &v.FailedChecks, &v.Checks, &v.Evidence, &v.ExecutedBy, &v.ExecutedAt); e != nil {
			operational.Failure(c, 500, "Unable to read compliance audits")
			return
		}
		items = append(items, v)
	}
	c.JSON(200, gin.H{"success": true, "message": "Compliance audits retrieved successfully", "data": items})
}
func (h *Handler) RunAudit(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := operational.ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q request
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid compliance audit payload", "error": e.Error()})
		return
	}
	passed := 0
	for i := range q.Checks {
		q.Checks[i].Status = strings.ToUpper(q.Checks[i].Status)
		if q.Checks[i].Status == "PASS" {
			passed++
		}
	}
	failed := len(q.Checks) - passed
	score := float64(passed) * 100 / float64(len(q.Checks))
	status := "COMPLIANT"
	if failed > 0 {
		status = "NON_COMPLIANT"
	}
	var v record
	e := h.db.QueryRow(c, `INSERT INTO compliance_audits(id,organization_id,framework,scope,status,score,passed_checks,failed_checks,checks,evidence,executed_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,framework,scope,status,score,passed_checks,failed_checks,checks,evidence,executed_by,executed_at`, uuid.New(), org, strings.ToUpper(strings.TrimSpace(q.Framework)), strings.TrimSpace(q.Scope), status, score, passed, failed, q.Checks, q.Evidence, actor).Scan(&v.ID, &v.Framework, &v.Scope, &v.Status, &v.Score, &v.PassedChecks, &v.FailedChecks, &v.Checks, &v.Evidence, &v.ExecutedBy, &v.ExecutedAt)
	if e != nil {
		operational.Failure(c, 500, "Compliance audit could not be stored")
		return
	}
	c.JSON(201, gin.H{"success": true, "message": "Compliance audit completed and stored", "data": v})
}
