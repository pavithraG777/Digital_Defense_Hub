package operational

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"time"
)

type ActionRequest struct {
	TargetType string         `json:"target_type" binding:"required,max=80"`
	TargetID   string         `json:"target_id" binding:"required,max=255"`
	ActionType string         `json:"action_type" binding:"required,max=100"`
	Reason     string         `json:"reason" binding:"required,max=1000"`
	Parameters map[string]any `json:"parameters"`
}
type Action struct {
	ID          uuid.UUID      `json:"id"`
	Module      string         `json:"module"`
	TargetType  string         `json:"target_type"`
	TargetID    string         `json:"target_id"`
	ActionType  string         `json:"action_type"`
	Status      string         `json:"status"`
	Reason      string         `json:"reason"`
	Parameters  map[string]any `json:"parameters"`
	Result      map[string]any `json:"result"`
	RequestedBy uuid.UUID      `json:"requested_by"`
	RequestedAt time.Time      `json:"requested_at"`
	CompletedBy *uuid.UUID     `json:"completed_by,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
}
type ActionStore struct {
	DB     *pgxpool.Pool
	Module string
}

const actionColumns = `id,module,target_type,target_id,action_type,status,reason,parameters,result,requested_by,requested_at,completed_by,completed_at`

type actionScanner interface{ Scan(...any) error }

func scanAction(s actionScanner) (Action, error) {
	var v Action
	err := s.Scan(&v.ID, &v.Module, &v.TargetType, &v.TargetID, &v.ActionType, &v.Status, &v.Reason, &v.Parameters, &v.Result, &v.RequestedBy, &v.RequestedAt, &v.CompletedBy, &v.CompletedAt)
	return v, err
}
func (s ActionStore) Create(c *gin.Context, forcedAction string) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q ActionRequest
	if err := c.ShouldBindJSON(&q); err != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid action payload", "error": err.Error()})
		return
	}
	if forcedAction != "" {
		q.ActionType = forcedAction
	}
	q.TargetType = strings.ToUpper(strings.TrimSpace(q.TargetType))
	q.ActionType = strings.ToUpper(strings.TrimSpace(q.ActionType))
	v, err := scanAction(s.DB.QueryRow(c, `INSERT INTO operational_actions(id,organization_id,module,target_type,target_id,action_type,status,reason,parameters,requested_by) VALUES($1,$2,$3,$4,$5,$6,'REQUESTED',$7,$8,$9) RETURNING `+actionColumns, uuid.New(), org, s.Module, q.TargetType, strings.TrimSpace(q.TargetID), q.ActionType, strings.TrimSpace(q.Reason), q.Parameters, actor))
	if err != nil {
		Failure(c, 500, "Action request could not be stored")
		return
	}
	c.JSON(202, gin.H{"success": true, "message": "Action request stored for authorized execution", "data": v})
}
func (s ActionStore) List(c *gin.Context) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, err := s.DB.Query(c, `SELECT `+actionColumns+` FROM operational_actions WHERE organization_id=$1 AND module=$2 ORDER BY requested_at DESC LIMIT 500`, org, s.Module)
	if err != nil {
		Failure(c, 500, "Actions could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]Action, 0)
	for rows.Next() {
		v, err := scanAction(rows)
		if err != nil {
			Failure(c, 500, "Actions could not be read")
			return
		}
		items = append(items, v)
	}
	c.JSON(200, gin.H{"success": true, "data": items})
}
func (s ActionStore) Get(c *gin.Context, idText string) {
	org, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	id, err := uuid.Parse(idText)
	if err != nil {
		Failure(c, 400, "Invalid action ID")
		return
	}
	v, err := scanAction(s.DB.QueryRow(c, `SELECT `+actionColumns+` FROM operational_actions WHERE organization_id=$1 AND module=$2 AND id=$3`, org, s.Module, id))
	if err == pgx.ErrNoRows {
		Failure(c, 404, "Action not found")
		return
	}
	if err != nil {
		Failure(c, 500, "Action could not be retrieved")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": v})
}
