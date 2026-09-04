package policy

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
	"strings"
)

type Handler struct{ db *pgxpool.Pool }
type rule struct {
	Field    string `json:"field" binding:"required"`
	Operator string `json:"operator" binding:"required,oneof=EQUALS NOT_EQUALS EXISTS"`
	Value    any    `json:"value"`
	Effect   string `json:"effect" binding:"required,oneof=ALLOW DENY"`
	Reason   string `json:"reason" binding:"required"`
}
type request struct {
	PolicyCode string         `json:"policy_code" binding:"required,max=100"`
	Subject    map[string]any `json:"subject" binding:"required"`
	Rules      []rule         `json:"rules" binding:"required,min=1,dive"`
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.db = db
	g := p.Group("/policy")
	g.POST("/evaluate", middleware.RequirePermission(db, "AI_ANALYSIS_EXECUTE"), h.EvaluatePolicy)
	g.GET("/evaluations", middleware.RequirePermission(db, "ANALYSIS_VIEW"), h.ListEvaluations)
}
func (h *Handler) EvaluatePolicy(c *gin.Context) {
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
		c.JSON(400, gin.H{"success": false, "message": "Invalid policy payload", "error": e.Error()})
		return
	}
	decision := "ALLOW"
	reasons := make([]string, 0)
	for _, r := range q.Rules {
		actual, exists := q.Subject[r.Field]
		matched := r.Operator == "EXISTS" && exists || (r.Operator == "EQUALS" && exists && fmt.Sprint(actual) == fmt.Sprint(r.Value)) || (r.Operator == "NOT_EQUALS" && (!exists || fmt.Sprint(actual) != fmt.Sprint(r.Value)))
		if matched {
			reasons = append(reasons, r.Reason)
			if r.Effect == "DENY" {
				decision = "DENY"
			}
		}
	}
	id := uuid.New()
	_, e := h.db.Exec(c, `INSERT INTO policy_evaluations(id,organization_id,policy_code,subject,rules,decision,reasons,evaluated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, org, strings.ToUpper(strings.TrimSpace(q.PolicyCode)), q.Subject, q.Rules, decision, reasons, actor)
	if e != nil {
		operational.Failure(c, 500, "Policy evaluation could not be stored")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": gin.H{"id": id, "decision": decision, "reasons": reasons}})
}
func (h *Handler) ListEvaluations(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, e := h.db.Query(c, `SELECT id,policy_code,subject,rules,decision,reasons,evaluated_by,evaluated_at FROM policy_evaluations WHERE organization_id=$1 ORDER BY evaluated_at DESC LIMIT 500`, org)
	if e != nil {
		operational.Failure(c, 500, "Policy evaluations could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]gin.H, 0)
	for rows.Next() {
		var id, actor uuid.UUID
		var code, decision string
		var subject map[string]any
		var rules, reasons any
		var at any
		if e = rows.Scan(&id, &code, &subject, &rules, &decision, &reasons, &actor, &at); e != nil {
			operational.Failure(c, 500, "Policy evaluations could not be read")
			return
		}
		items = append(items, gin.H{"id": id, "policy_code": code, "subject": subject, "rules": rules, "decision": decision, "reasons": reasons, "evaluated_by": actor, "evaluated_at": at})
	}
	c.JSON(200, gin.H{"success": true, "data": items})
}
