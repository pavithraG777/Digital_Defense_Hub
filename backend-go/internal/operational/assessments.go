package operational

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"time"
)

type Finding struct {
	Code           string `json:"code" binding:"required,max=100"`
	Title          string `json:"title" binding:"required,max=255"`
	Severity       string `json:"severity" binding:"required,oneof=LOW MEDIUM HIGH CRITICAL"`
	Status         string `json:"status" binding:"required,oneof=OPEN PASS RESOLVED"`
	Evidence       string `json:"evidence" binding:"required,max=4000"`
	Recommendation string `json:"recommendation" binding:"omitempty,max=4000"`
}
type AssessmentRequest struct {
	TargetType string         `json:"target_type" binding:"required,max=80"`
	TargetID   string         `json:"target_id" binding:"required,max=255"`
	Profile    string         `json:"profile" binding:"required,max=100"`
	Findings   []Finding      `json:"findings" binding:"required,min=1,dive"`
	Evidence   map[string]any `json:"evidence"`
}
type Assessment struct {
	ID         uuid.UUID      `json:"id"`
	Module     string         `json:"module"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Profile    string         `json:"profile"`
	Status     string         `json:"status"`
	Score      int            `json:"score"`
	Findings   []Finding      `json:"findings"`
	Evidence   map[string]any `json:"evidence"`
	AssessedBy uuid.UUID      `json:"assessed_by"`
	AssessedAt time.Time      `json:"assessed_at"`
}
type AssessmentStore struct {
	DB     *pgxpool.Pool
	Module string
}

const assessmentColumns = `id,module,target_type,target_id,profile,status,score,findings,evidence,assessed_by,assessed_at`

type assessmentScanner interface{ Scan(...any) error }

func scanAssessment(s assessmentScanner) (Assessment, error) {
	var v Assessment
	e := s.Scan(&v.ID, &v.Module, &v.TargetType, &v.TargetID, &v.Profile, &v.Status, &v.Score, &v.Findings, &v.Evidence, &v.AssessedBy, &v.AssessedAt)
	return v, e
}
func (s AssessmentStore) Create(c *gin.Context) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q AssessmentRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid assessment payload", "error": e.Error()})
		return
	}
	weights := map[string]int{"LOW": 10, "MEDIUM": 30, "HIGH": 65, "CRITICAL": 100}
	score := 0
	for i := range q.Findings {
		q.Findings[i].Severity = strings.ToUpper(q.Findings[i].Severity)
		q.Findings[i].Status = strings.ToUpper(q.Findings[i].Status)
		if q.Findings[i].Status == "OPEN" && weights[q.Findings[i].Severity] > score {
			score = weights[q.Findings[i].Severity]
		}
	}
	v, e := scanAssessment(s.DB.QueryRow(c, `INSERT INTO operational_assessments(id,organization_id,module,target_type,target_id,profile,score,findings,evidence,assessed_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+assessmentColumns, uuid.New(), org, s.Module, strings.ToUpper(strings.TrimSpace(q.TargetType)), strings.TrimSpace(q.TargetID), strings.ToUpper(strings.TrimSpace(q.Profile)), score, q.Findings, q.Evidence, actor))
	if e != nil {
		Failure(c, 500, "Assessment could not be stored")
		return
	}
	c.JSON(201, gin.H{"success": true, "message": "Assessment completed and stored", "data": v})
}
func (s AssessmentStore) List(c *gin.Context) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, e := s.DB.Query(c, `SELECT `+assessmentColumns+` FROM operational_assessments WHERE organization_id=$1 AND module=$2 ORDER BY assessed_at DESC LIMIT 500`, org, s.Module)
	if e != nil {
		Failure(c, 500, "Assessments could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]Assessment, 0)
	for rows.Next() {
		v, e := scanAssessment(rows)
		if e != nil {
			Failure(c, 500, "Assessments could not be read")
			return
		}
		items = append(items, v)
	}
	c.JSON(200, gin.H{"success": true, "data": items})
}
func (s AssessmentStore) Get(c *gin.Context, idText string) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	id, e := uuid.Parse(idText)
	if e != nil {
		Failure(c, 400, "Invalid assessment ID")
		return
	}
	v, e := scanAssessment(s.DB.QueryRow(c, `SELECT `+assessmentColumns+` FROM operational_assessments WHERE organization_id=$1 AND module=$2 AND id=$3`, org, s.Module, id))
	if e == pgx.ErrNoRows {
		Failure(c, 404, "Assessment not found")
		return
	}
	if e != nil {
		Failure(c, 500, "Assessment could not be retrieved")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": v})
}
