package configassessment

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
type finding struct {
	Rule           string `json:"rule" binding:"required"`
	Status         string `json:"status" binding:"required,oneof=PASS FAIL"`
	Observed       string `json:"observed" binding:"required"`
	Recommendation string `json:"recommendation"`
}
type request struct {
	TargetType       string         `json:"target_type" binding:"required,max=80"`
	TargetIdentifier string         `json:"target_identifier" binding:"required,max=255"`
	Profile          string         `json:"profile" binding:"required,max=100"`
	Findings         []finding      `json:"findings" binding:"required,min=1,dive"`
	Evidence         map[string]any `json:"evidence"`
}
type record struct {
	ID               uuid.UUID      `json:"id"`
	TargetType       string         `json:"target_type"`
	TargetIdentifier string         `json:"target_identifier"`
	Profile          string         `json:"profile"`
	Status           string         `json:"status"`
	Score            float64        `json:"score"`
	PassedChecks     int            `json:"passed_checks"`
	FailedChecks     int            `json:"failed_checks"`
	Findings         []finding      `json:"findings"`
	Evidence         map[string]any `json:"evidence"`
	AssessedBy       uuid.UUID      `json:"assessed_by"`
	AssessedAt       time.Time      `json:"assessed_at"`
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.db = db
	g := p.Group("/config-assessment")
	g.GET("", middleware.RequirePermission(db, "THREAT_VIEW"), h.GetAssessment)
	g.POST("", middleware.RequirePermission(db, "THREAT_MANAGE"), h.CreateAssessment)
}
func (h *Handler) GetAssessment(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, e := h.db.Query(c, `SELECT id,target_type,target_identifier,profile,status,score,passed_checks,failed_checks,findings,evidence,assessed_by,assessed_at FROM configuration_assessments WHERE organization_id=$1 ORDER BY assessed_at DESC LIMIT 200`, org)
	if e != nil {
		operational.Failure(c, 500, "Unable to list configuration assessments")
		return
	}
	defer rows.Close()
	items := make([]record, 0)
	for rows.Next() {
		var v record
		if e = rows.Scan(&v.ID, &v.TargetType, &v.TargetIdentifier, &v.Profile, &v.Status, &v.Score, &v.PassedChecks, &v.FailedChecks, &v.Findings, &v.Evidence, &v.AssessedBy, &v.AssessedAt); e != nil {
			operational.Failure(c, 500, "Unable to read configuration assessments")
			return
		}
		items = append(items, v)
	}
	c.JSON(200, gin.H{"success": true, "message": "Configuration assessments retrieved successfully", "data": items})
}
func (h *Handler) CreateAssessment(c *gin.Context) {
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
		c.JSON(400, gin.H{"success": false, "message": "Invalid configuration assessment payload", "error": e.Error()})
		return
	}
	passed := 0
	for i := range q.Findings {
		q.Findings[i].Status = strings.ToUpper(q.Findings[i].Status)
		if q.Findings[i].Status == "PASS" {
			passed++
		}
	}
	failed := len(q.Findings) - passed
	score := float64(passed) * 100 / float64(len(q.Findings))
	status := "COMPLIANT"
	if failed > 0 {
		status = "NON_COMPLIANT"
	}
	var v record
	e := h.db.QueryRow(c, `INSERT INTO configuration_assessments(id,organization_id,target_type,target_identifier,profile,status,score,passed_checks,failed_checks,findings,evidence,assessed_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id,target_type,target_identifier,profile,status,score,passed_checks,failed_checks,findings,evidence,assessed_by,assessed_at`, uuid.New(), org, strings.ToUpper(strings.TrimSpace(q.TargetType)), strings.TrimSpace(q.TargetIdentifier), strings.ToUpper(strings.TrimSpace(q.Profile)), status, score, passed, failed, q.Findings, q.Evidence, actor).Scan(&v.ID, &v.TargetType, &v.TargetIdentifier, &v.Profile, &v.Status, &v.Score, &v.PassedChecks, &v.FailedChecks, &v.Findings, &v.Evidence, &v.AssessedBy, &v.AssessedAt)
	if e != nil {
		operational.Failure(c, 500, "Configuration assessment could not be stored")
		return
	}
	c.JSON(201, gin.H{"success": true, "message": "Configuration assessment completed and stored", "data": v})
}
