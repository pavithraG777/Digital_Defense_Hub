package deepfakeforensics

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type reviewInput struct {
	Decision  string `json:"decision" binding:"required,oneof=CONFIRMED_AUTHENTIC CONFIRMED_MANIPULATED INCONCLUSIVE ESCALATED"`
	Rationale string `json:"rationale" binding:"required,max=8000"`
}
type annotationInput struct {
	AnnotationType string `json:"annotation_type" binding:"required,oneof=NOTE REGION EVIDENCE ESCALATION"`
	Body           string `json:"body" binding:"required,max=8000"`
	Region         any    `json:"region"`
}
type caseLinkInput struct {
	InvestigationCaseID *uuid.UUID `json:"investigation_case_id"`
	IncidentID          *uuid.UUID `json:"incident_id"`
}

func (h *Handler) reviewIdentity(c *gin.Context) (uuid.UUID, uuid.UUID, uuid.UUID, bool) {
	org, user, ok := h.authenticatedIdentity(c)
	if !ok || h.reviewDB == nil {
		if ok {
			response.InternalServerError(c, "Review workflow is unavailable", nil)
		}
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}
	job, ok := handlerPathUUID(c, "analysis_job_id")
	if !ok {
		response.BadRequest(c, "Invalid analysis job ID", nil)
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}
	var exists bool
	if err := h.reviewDB.QueryRow(c, `SELECT EXISTS(SELECT 1 FROM ai_analysis_jobs WHERE organization_id=$1 AND id=$2)`, org, job).Scan(&exists); err != nil || !exists {
		response.NotFound(c, "Media analysis job not found", nil)
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}
	return org, user, job, true
}
func (h *Handler) CreateReview(c *gin.Context) {
	org, user, job, ok := h.reviewIdentity(c)
	if !ok {
		return
	}
	var in reviewInput
	if c.ShouldBindJSON(&in) != nil || strings.TrimSpace(in.Rationale) == "" {
		response.BadRequest(c, "A decision and rationale are required", nil)
		return
	}
	var id uuid.UUID
	err := h.reviewDB.QueryRow(c, `INSERT INTO media_forensic_reviews(organization_id,analysis_job_id,reviewer_user_id,decision,rationale) VALUES($1,$2,$3,$4,$5) RETURNING id`, org, job, user, in.Decision, strings.TrimSpace(in.Rationale)).Scan(&id)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to save review decision")
		return
	}
	response.Created(c, "Review decision saved", gin.H{"id": id, "decision": in.Decision})
}
func (h *Handler) CreateAnnotation(c *gin.Context) {
	org, user, job, ok := h.reviewIdentity(c)
	if !ok {
		return
	}
	var in annotationInput
	if c.ShouldBindJSON(&in) != nil || strings.TrimSpace(in.Body) == "" {
		response.BadRequest(c, "An annotation type and body are required", nil)
		return
	}
	var id uuid.UUID
	err := h.reviewDB.QueryRow(c, `INSERT INTO media_forensic_annotations(organization_id,analysis_job_id,created_by,annotation_type,body,region) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`, org, job, user, in.AnnotationType, strings.TrimSpace(in.Body), in.Region).Scan(&id)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to save annotation")
		return
	}
	response.Created(c, "Annotation saved", gin.H{"id": id})
}
func (h *Handler) CreateCaseLink(c *gin.Context) {
	org, user, job, ok := h.reviewIdentity(c)
	if !ok {
		return
	}
	var in caseLinkInput
	if c.ShouldBindJSON(&in) != nil || (in.InvestigationCaseID == nil && in.IncidentID == nil) {
		response.BadRequest(c, "An investigation case or incident is required", nil)
		return
	}
	var id uuid.UUID
	err := h.reviewDB.QueryRow(c, `INSERT INTO media_forensic_case_links(organization_id,analysis_job_id,investigation_case_id,incident_id,linked_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id`, org, job, in.InvestigationCaseID, in.IncidentID, user).Scan(&id)
	if err != nil {
		response.Error(c, http.StatusConflict, "Case or incident link already exists", nil)
		return
	}
	response.Created(c, "Case link saved", gin.H{"id": id})
}
func (h *Handler) GetReviewWorkflow(c *gin.Context) {
	org, _, job, ok := h.reviewIdentity(c)
	if !ok {
		return
	}
	out := gin.H{}
	for key, q := range map[string]string{"reviews": `SELECT id,decision,rationale,reviewer_user_id,reviewed_at FROM media_forensic_reviews WHERE organization_id=$1 AND analysis_job_id=$2 ORDER BY reviewed_at DESC`, `annotations`: `SELECT id,annotation_type,body,region,created_by,created_at FROM media_forensic_annotations WHERE organization_id=$1 AND analysis_job_id=$2 ORDER BY created_at DESC`, `case_links`: `SELECT id,investigation_case_id,incident_id,linked_by,created_at FROM media_forensic_case_links WHERE organization_id=$1 AND analysis_job_id=$2 ORDER BY created_at DESC`} {
		rows, err := h.reviewDB.Query(c, q, org, job)
		if err != nil {
			handleMediaAPIError(c, err, "Unable to load review workflow")
			return
		}
		values, err := rowsToMaps(rows)
		rows.Close()
		if err != nil {
			handleMediaAPIError(c, err, "Unable to load review workflow")
			return
		}
		out[key] = values
	}
	response.OK(c, "Review workflow retrieved", out)
}

func rowsToMaps(rows pgx.Rows) ([]gin.H, error) {
	fields := rows.FieldDescriptions()
	out := make([]gin.H, 0)
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		item := gin.H{}
		for i, field := range fields {
			item[string(field.Name)] = values[i]
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
