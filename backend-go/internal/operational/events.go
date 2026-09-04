package operational

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"time"
)

type EventRequest struct {
	SubjectType string         `json:"subject_type" binding:"required,max=80"`
	SubjectID   string         `json:"subject_id" binding:"required,max=255"`
	EventType   string         `json:"event_type" binding:"required,max=100"`
	Severity    string         `json:"severity" binding:"required,oneof=LOW MEDIUM HIGH CRITICAL"`
	RiskScore   int            `json:"risk_score" binding:"gte=0,lte=100"`
	Payload     map[string]any `json:"payload"`
}
type Event struct {
	ID          uuid.UUID      `json:"id"`
	Module      string         `json:"module"`
	SubjectType string         `json:"subject_type"`
	SubjectID   string         `json:"subject_id"`
	EventType   string         `json:"event_type"`
	Severity    string         `json:"severity"`
	RiskScore   int            `json:"risk_score"`
	Status      string         `json:"status"`
	Payload     map[string]any `json:"payload"`
	CreatedBy   uuid.UUID      `json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}
type EventStore struct {
	DB     *pgxpool.Pool
	Module string
}

func (s EventStore) Submit(c *gin.Context) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q EventRequest
	if err := c.ShouldBindJSON(&q); err != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid event payload", "error": err.Error()})
		return
	}
	q.SubjectType = strings.ToUpper(strings.TrimSpace(q.SubjectType))
	q.EventType = strings.ToUpper(strings.TrimSpace(q.EventType))
	q.Severity = strings.ToUpper(q.Severity)
	var v Event
	err := s.DB.QueryRow(c, `INSERT INTO operational_events(id,organization_id,module,subject_type,subject_id,event_type,severity,risk_score,payload,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id,module,subject_type,subject_id,event_type,severity,risk_score,status,payload,created_by,created_at,updated_at`, uuid.New(), org, s.Module, q.SubjectType, strings.TrimSpace(q.SubjectID), q.EventType, q.Severity, q.RiskScore, q.Payload, actor).Scan(&v.ID, &v.Module, &v.SubjectType, &v.SubjectID, &v.EventType, &v.Severity, &v.RiskScore, &v.Status, &v.Payload, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		Failure(c, 500, "Event could not be stored")
		return
	}
	c.JSON(201, gin.H{"success": true, "message": "Event stored successfully", "data": v})
}
func (s EventStore) List(c *gin.Context, minimumRisk int) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, err := s.DB.Query(c, `SELECT id,module,subject_type,subject_id,event_type,severity,risk_score,status,payload,created_by,created_at,updated_at FROM operational_events WHERE organization_id=$1 AND module=$2 AND risk_score >= $3 ORDER BY created_at DESC LIMIT 500`, org, s.Module, minimumRisk)
	if err != nil {
		Failure(c, 500, "Events could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]Event, 0)
	for rows.Next() {
		var v Event
		if err = rows.Scan(&v.ID, &v.Module, &v.SubjectType, &v.SubjectID, &v.EventType, &v.Severity, &v.RiskScore, &v.Status, &v.Payload, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt); err != nil {
			Failure(c, 500, "Events could not be read")
			return
		}
		items = append(items, v)
	}
	c.JSON(200, gin.H{"success": true, "message": "Events retrieved successfully", "data": items})
}

func (s EventStore) Get(c *gin.Context, idText string) {
	organizationID, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	id, err := uuid.Parse(idText)
	if err != nil {
		Failure(c, 400, "Invalid event ID")
		return
	}
	var v Event
	err = s.DB.QueryRow(c, `SELECT id,module,subject_type,subject_id,event_type,severity,risk_score,status,payload,created_by,created_at,updated_at FROM operational_events WHERE organization_id=$1 AND module=$2 AND id=$3`, organizationID, s.Module, id).Scan(&v.ID, &v.Module, &v.SubjectType, &v.SubjectID, &v.EventType, &v.Severity, &v.RiskScore, &v.Status, &v.Payload, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt)
	if err == pgx.ErrNoRows {
		Failure(c, 404, "Event not found")
		return
	}
	if err != nil {
		Failure(c, 500, "Event could not be retrieved")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": v})
}
func (s EventStore) Baseline(c *gin.Context, subjectID string) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	var count int
	var avg, max float64
	err := s.DB.QueryRow(c, `SELECT count(*),COALESCE(avg(risk_score),0),COALESCE(max(risk_score),0) FROM operational_events WHERE organization_id=$1 AND module=$2 AND subject_id=$3`, org, s.Module, subjectID).Scan(&count, &avg, &max)
	if err != nil {
		Failure(c, 500, "Behavior baseline could not be calculated")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": gin.H{"subject_id": subjectID, "event_count": count, "average_risk_score": avg, "maximum_risk_score": max, "data_available": count > 0}})
}
