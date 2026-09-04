package incidentresponse

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
	"strings"
)

type Handler struct{ db *pgxpool.Pool }
type executeRequest struct {
	IncidentID   string         `json:"incident_id" binding:"required,uuid"`
	PlaybookCode string         `json:"playbook_code" binding:"required,max=100"`
	Parameters   map[string]any `json:"parameters"`
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.db = db
	g := p.Group("/incident-response")
	g.POST("/playbooks/execute", middleware.RequirePermission(db, "INCIDENT_RESPONSE_EXECUTE"), h.ExecutePlaybook)
	g.GET("/incidents", middleware.RequirePermission(db, "INCIDENT_RESPONSE_VIEW"), h.ListIncidents)
}
func (h *Handler) ListIncidents(c *gin.Context) {
	operational.ListIncidentStage(c, h.db, "incident response", []string{})
}
func (h *Handler) ExecutePlaybook(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := operational.ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q executeRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid playbook request", "error": e.Error()})
		return
	}
	incidentID, _ := uuid.Parse(q.IncidentID)
	id := uuid.New()
	tag, e := h.db.Exec(c, `INSERT INTO incident_playbook_executions(id,organization_id,incident_id,playbook_code,status,parameters,requested_by) SELECT $1,$2,$3,$4,'AWAITING_EXECUTOR',$5,$6 WHERE EXISTS(SELECT 1 FROM incidents WHERE organization_id=$2 AND id=$3 AND deleted_at IS NULL)`, id, org, incidentID, strings.ToUpper(strings.TrimSpace(q.PlaybookCode)), q.Parameters, actor)
	if e != nil {
		operational.Failure(c, 500, "Playbook request could not be stored")
		return
	}
	if tag.RowsAffected() == 0 {
		operational.Failure(c, 404, "Incident not found")
		return
	}
	c.JSON(202, gin.H{"success": true, "message": "Playbook request recorded for an authorized executor", "data": gin.H{"id": id, "incident_id": incidentID, "status": "AWAITING_EXECUTOR"}})
}
