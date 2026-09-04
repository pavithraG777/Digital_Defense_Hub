package metadata

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct{ store operational.AssessmentStore }
type request struct {
	TargetID         string         `json:"target_id" binding:"required,max=255"`
	Metadata         map[string]any `json:"metadata" binding:"required"`
	RequiredFields   []string       `json:"required_fields"`
	ProhibitedFields []string       `json:"prohibited_fields"`
	Expected         map[string]any `json:"expected"`
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.store = operational.AssessmentStore{DB: db, Module: "METADATA"}
	g := p.Group("/metadata")
	g.POST("/validate", middleware.RequirePermission(db, "ANALYSIS_EXECUTE"), h.ValidateMetadata)
	g.GET("", middleware.RequirePermission(db, "ANALYSIS_VIEW"), h.ListMetadata)
	g.GET("/:metadata_id", middleware.RequirePermission(db, "ANALYSIS_VIEW"), h.GetMetadata)
}
func (h *Handler) ValidateMetadata(c *gin.Context) {
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
		c.JSON(400, gin.H{"success": false, "message": "Invalid metadata validation payload", "error": e.Error()})
		return
	}
	findings := make([]operational.Finding, 0)
	for _, key := range q.RequiredFields {
		if _, exists := q.Metadata[key]; !exists {
			findings = append(findings, operational.Finding{Code: "MISSING_" + key, Title: "Required metadata is missing", Severity: "HIGH", Status: "OPEN", Evidence: key, Recommendation: "Provide the required metadata field."})
		}
	}
	for _, key := range q.ProhibitedFields {
		if _, exists := q.Metadata[key]; exists {
			findings = append(findings, operational.Finding{Code: "PROHIBITED_" + key, Title: "Prohibited metadata is present", Severity: "HIGH", Status: "OPEN", Evidence: key, Recommendation: "Remove the prohibited metadata field."})
		}
	}
	for key, want := range q.Expected {
		if got, exists := q.Metadata[key]; !exists || fmt.Sprint(got) != fmt.Sprint(want) {
			findings = append(findings, operational.Finding{Code: "MISMATCH_" + key, Title: "Metadata value does not match", Severity: "MEDIUM", Status: "OPEN", Evidence: fmt.Sprintf("expected=%v observed=%v", want, got), Recommendation: "Correct the metadata value."})
		}
	}
	score := 0
	if len(findings) > 0 {
		score = 65
	}
	id := uuid.New()
	_, e := h.store.DB.Exec(c, `INSERT INTO operational_assessments(id,organization_id,module,target_type,target_id,profile,score,findings,evidence,assessed_by) VALUES($1,$2,'METADATA','MEDIA',$3,'METADATA_VALIDATION',$4,$5,$6,$7)`, id, org, q.TargetID, score, findings, q.Metadata, actor)
	if e != nil {
		operational.Failure(c, 500, "Metadata validation could not be stored")
		return
	}
	c.JSON(201, gin.H{"success": true, "message": "Metadata validation completed", "data": gin.H{"id": id, "valid": len(findings) == 0, "score": score, "findings": findings}})
}
func (h *Handler) ListMetadata(c *gin.Context) { h.store.List(c) }
func (h *Handler) GetMetadata(c *gin.Context)  { h.store.Get(c, c.Param("metadata_id")) }
