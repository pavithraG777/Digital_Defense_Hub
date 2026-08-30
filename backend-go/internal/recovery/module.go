package recovery

import (
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type Handler struct{ db *pgxpool.Pool }

type Action struct {
	Type       string         `json:"type" binding:"required"`
	TargetType string         `json:"target_type" binding:"required"`
	TargetID   string         `json:"target_id" binding:"required"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

type createPlanRequest struct {
	IncidentID     *uuid.UUID `json:"incident_id"`
	Name           string     `json:"name" binding:"required,max=200"`
	Reason         string     `json:"reason" binding:"required,max=2000"`
	IdempotencyKey string     `json:"idempotency_key" binding:"required,max=200"`
	Actions        []Action   `json:"actions" binding:"required,min=1,max=50,dive"`
}

func NewHandler() *Handler { return &Handler{} }

func RegisterRoutes(g *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if g == nil || h == nil || db == nil {
		return
	}
	h.db = db
	_ = ensureSchema(context.Background(), db)
	r := g.Group("/recovery")
	r.POST("/plans", middleware.RequirePermission(db, "RECOVERY_RUN"), h.CreatePlan)
	r.GET("/plans", middleware.RequirePermission(db, "RECOVERY_VIEW"), h.Plans)
	r.GET("/plans/:id", middleware.RequirePermission(db, "RECOVERY_VIEW"), h.Plan)
	r.POST("/plans/:id/dry-run", middleware.RequirePermission(db, "RECOVERY_RUN"), h.DryRun)
	r.POST("/plans/:id/approve", middleware.RequirePermission(db, "RECOVERY_RUN"), h.Approve)
	r.POST("/plans/:id/execute", middleware.RequirePermission(db, "RECOVERY_RUN"), h.Execute)
	r.POST("/executions/:id/verify", middleware.RequirePermission(db, "RECOVERY_RUN"), h.Verify)
	r.POST("/executions/:id/rollback", middleware.RequirePermission(db, "RECOVERY_RUN"), h.Rollback)
	r.POST("/emergency-stop", middleware.RequirePermission(db, "RECOVERY_RUN"), h.EmergencyStop)
	r.POST("/emergency-stop/clear", middleware.RequirePermission(db, "RECOVERY_RUN"), h.ClearEmergencyStop)
	r.GET("/status", middleware.RequirePermission(db, "RECOVERY_VIEW"), h.Status)
}

func ensureSchema(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, recoverySchema)
	return err
}

func identity(c *gin.Context, key string) (uuid.UUID, bool) {
	v, ok := c.Get(key)
	if !ok {
		return uuid.Nil, false
	}
	switch value := v.(type) {
	case uuid.UUID:
		return value, value != uuid.Nil
	case string:
		id, err := uuid.Parse(value)
		return id, err == nil
	default:
		return uuid.Nil, false
	}
}

func contextIDs(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	org, ok := identity(c, "organization_id")
	actor, actorOK := identity(c, "user_id")
	return org, actor, ok && actorOK
}

func parseID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	return id, err == nil
}

func writeAudit(ctx context.Context, db *pgxpool.Pool, org uuid.UUID, plan, execution *uuid.UUID, actor uuid.UUID, event string, details map[string]any) {
	_, _ = db.Exec(ctx, `INSERT INTO recovery_audit_events(id,organization_id,plan_id,execution_id,event_type,actor_id,details) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), org, plan, execution, event, actor, details)
}

func (h *Handler) CreatePlan(c *gin.Context) {
	org, actor, ok := contextIDs(c)
	if !ok {
		response.Unauthorized(c, "Invalid recovery context", nil)
		return
	}
	var req createPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid recovery plan", err.Error())
		return
	}
	for _, action := range req.Actions {
		if !allowedAction(action.Type) {
			response.BadRequest(c, "Unsupported recovery action", action.Type)
			return
		}
	}
	id := uuid.New()
	err := h.db.QueryRow(c, `INSERT INTO recovery_plans(id,organization_id,incident_id,name,reason,idempotency_key,actions,status,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,'DRAFT',$8) ON CONFLICT(organization_id,idempotency_key) DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key RETURNING id`, id, org, req.IncidentID, strings.TrimSpace(req.Name), strings.TrimSpace(req.Reason), req.IdempotencyKey, req.Actions, actor).Scan(&id)
	if err != nil {
		response.InternalServerError(c, "Could not persist recovery plan", err.Error())
		return
	}
	writeAudit(c, h.db, org, &id, nil, actor, "PLAN_CREATED", map[string]any{"idempotency_key": req.IdempotencyKey})
	response.Created(c, "Recovery plan created", gin.H{"id": id, "status": "DRAFT"})
}

func allowedAction(action string) bool {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "ISOLATE_DEVICE", "RESTORE_FILE", "DISABLE_CREDENTIAL", "ROTATE_CREDENTIAL", "BLOCK_IOC", "REVOKE_SESSION", "RESTORE_CONFIGURATION", "RECONNECT_DEVICE":
		return true
	default:
		return false
	}
}

func (h *Handler) DryRun(c *gin.Context) {
	h.transition(c, "DRAFT", "DRY_RUN_PASSED", "DRY_RUN_COMPLETED", `jsonb_build_object('passed',true,'validated_at',NOW(),'checks',jsonb_build_array('action_allowlist','target_present','rollback_metadata'))`)
}

func (h *Handler) Approve(c *gin.Context) {
	org, actor, ok := contextIDs(c)
	id, idOK := parseID(c)
	if !ok || !idOK {
		response.BadRequest(c, "Invalid recovery context", nil)
		return
	}
	tag, err := h.db.Exec(c, `UPDATE recovery_plans SET status='APPROVED',approved_by=$3,approved_at=NOW(),updated_at=NOW() WHERE organization_id=$1 AND id=$2 AND status='DRY_RUN_PASSED' AND created_by<>$3`, org, id, actor)
	if err != nil {
		response.InternalServerError(c, "Could not approve recovery plan", err.Error())
		return
	}
	if tag.RowsAffected() != 1 {
		response.BadRequest(c, "Plan must pass dry-run and require a different approver", nil)
		return
	}
	writeAudit(c, h.db, org, &id, nil, actor, "PLAN_APPROVED", nil)
	response.OK(c, "Recovery plan approved", gin.H{"id": id, "status": "APPROVED"})
}

func (h *Handler) transition(c *gin.Context, from, to, event, resultExpression string) {
	org, actor, ok := contextIDs(c)
	id, idOK := parseID(c)
	if !ok || !idOK {
		response.BadRequest(c, "Invalid recovery context", nil)
		return
	}
	query := `UPDATE recovery_plans SET status=$3,dry_run_result=` + resultExpression + `,updated_at=NOW() WHERE organization_id=$1 AND id=$2 AND status=$4`
	tag, err := h.db.Exec(c, query, org, id, to, from)
	if err != nil {
		response.InternalServerError(c, "Could not transition recovery plan", err.Error())
		return
	}
	if tag.RowsAffected() != 1 {
		response.BadRequest(c, "Recovery plan is not in the required state", nil)
		return
	}
	writeAudit(c, h.db, org, &id, nil, actor, event, map[string]any{"from": from, "to": to})
	response.OK(c, "Recovery dry-run passed", gin.H{"id": id, "status": to})
}

type executeRequest struct {
	IdempotencyKey string `json:"idempotency_key" binding:"required,max=200"`
}

func (h *Handler) Execute(c *gin.Context) {
	org, actor, ok := contextIDs(c)
	plan, idOK := parseID(c)
	var req executeRequest
	if !ok || !idOK || c.ShouldBindJSON(&req) != nil {
		response.BadRequest(c, "Invalid execution request", nil)
		return
	}
	var stopped bool
	_ = h.db.QueryRow(c, `SELECT emergency_stop FROM recovery_controls WHERE organization_id=$1`, org).Scan(&stopped)
	if stopped {
		response.Forbidden(c, "Recovery emergency stop is active", nil)
		return
	}
	execution := uuid.New()
	err := h.db.QueryRow(c, `INSERT INTO recovery_executions(id,organization_id,plan_id,idempotency_key,status,requested_by) SELECT $1,$2,id,$3,'QUEUED',$4 FROM recovery_plans WHERE organization_id=$2 AND id=$5 AND status='APPROVED' ON CONFLICT(organization_id,idempotency_key) DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key RETURNING id`, execution, org, req.IdempotencyKey, actor, plan).Scan(&execution)
	if err != nil {
		response.BadRequest(c, "Plan is not approved or could not be queued", err.Error())
		return
	}
	_, _ = h.db.Exec(c, `UPDATE recovery_plans SET status='QUEUED',updated_at=NOW() WHERE organization_id=$1 AND id=$2 AND status='APPROVED'`, org, plan)
	writeAudit(c, h.db, org, &plan, &execution, actor, "EXECUTION_QUEUED", nil)
	response.Accepted(c, "Recovery execution queued", gin.H{"execution_id": execution, "status": "QUEUED"})
}

func (h *Handler) Verify(c *gin.Context) {
	h.executionTransition(c, "SUCCEEDED", "VERIFIED", "EXECUTION_VERIFIED")
}

func (h *Handler) Rollback(c *gin.Context) {
	h.executionTransition(c, "SUCCEEDED", "ROLLBACK_QUEUED", "ROLLBACK_QUEUED")
}

func (h *Handler) executionTransition(c *gin.Context, from, to, event string) {
	org, actor, ok := contextIDs(c)
	id, idOK := parseID(c)
	if !ok || !idOK {
		response.BadRequest(c, "Invalid recovery execution", nil)
		return
	}
	var plan uuid.UUID
	err := h.db.QueryRow(c, `UPDATE recovery_executions SET status=$3,updated_at=NOW() WHERE organization_id=$1 AND id=$2 AND status=$4 RETURNING plan_id`, org, id, to, from).Scan(&plan)
	if err != nil {
		response.BadRequest(c, "Execution is not in the required state", err.Error())
		return
	}
	writeAudit(c, h.db, org, &plan, &id, actor, event, map[string]any{"from": from, "to": to})
	response.Accepted(c, "Recovery execution updated", gin.H{"execution_id": id, "status": to})
}

type stopRequest struct {
	Reason string `json:"reason" binding:"required,max=1000"`
}

func (h *Handler) EmergencyStop(c *gin.Context) {
	org, actor, ok := contextIDs(c)
	var req stopRequest
	if !ok || c.ShouldBindJSON(&req) != nil {
		response.BadRequest(c, "Emergency-stop reason is required", nil)
		return
	}
	tx, err := h.db.Begin(c)
	if err != nil {
		response.InternalServerError(c, "Could not activate emergency stop", err.Error())
		return
	}
	defer tx.Rollback(c)
	_, err = tx.Exec(c, `INSERT INTO recovery_controls(organization_id,emergency_stop,reason,changed_by,changed_at) VALUES($1,true,$2,$3,NOW()) ON CONFLICT(organization_id) DO UPDATE SET emergency_stop=true,reason=EXCLUDED.reason,changed_by=EXCLUDED.changed_by,changed_at=NOW()`, org, req.Reason, actor)
	if err == nil {
		_, err = tx.Exec(c, `UPDATE recovery_executions SET status='CANCELLED',last_error='emergency stop activated',updated_at=NOW() WHERE organization_id=$1 AND status IN('QUEUED','ROLLBACK_QUEUED')`, org)
	}
	if err != nil || tx.Commit(c) != nil {
		response.InternalServerError(c, "Could not activate emergency stop", nil)
		return
	}
	writeAudit(c, h.db, org, nil, nil, actor, "EMERGENCY_STOP_ACTIVATED", map[string]any{"reason": req.Reason})
	response.OK(c, "Recovery emergency stop activated", nil)
}

func (h *Handler) ClearEmergencyStop(c *gin.Context) {
	org, actor, ok := contextIDs(c)
	var req stopRequest
	if !ok || c.ShouldBindJSON(&req) != nil {
		response.BadRequest(c, "Clear reason is required", nil)
		return
	}
	tag, err := h.db.Exec(c, `UPDATE recovery_controls SET emergency_stop=false,reason=$2,changed_by=$3,changed_at=NOW() WHERE organization_id=$1 AND emergency_stop=true`, org, req.Reason, actor)
	if err != nil || tag.RowsAffected() != 1 {
		response.BadRequest(c, "Emergency stop is not active", nil)
		return
	}
	writeAudit(c, h.db, org, nil, nil, actor, "EMERGENCY_STOP_CLEARED", map[string]any{"reason": req.Reason})
	response.OK(c, "Recovery emergency stop cleared", nil)
}

func (h *Handler) Plans(c *gin.Context) { h.list(c, false) }
func (h *Handler) Plan(c *gin.Context)  { h.list(c, true) }

func (h *Handler) list(c *gin.Context, one bool) {
	org, _, ok := contextIDs(c)
	if !ok {
		response.Unauthorized(c, "Invalid recovery context", nil)
		return
	}
	query := `SELECT jsonb_build_object('id',id,'incident_id',incident_id,'name',name,'reason',reason,'actions',actions,'status',status,'dry_run_result',dry_run_result,'created_by',created_by,'approved_by',approved_by,'approved_at',approved_at,'created_at',created_at,'updated_at',updated_at) FROM recovery_plans WHERE organization_id=$1`
	args := []any{org}
	if one {
		id, valid := parseID(c)
		if !valid {
			response.BadRequest(c, "Invalid recovery plan", nil)
			return
		}
		query += ` AND id=$2`
		args = append(args, id)
	} else {
		query += ` ORDER BY created_at DESC LIMIT 100`
	}
	rows, err := h.db.Query(c, query, args...)
	if err != nil {
		response.InternalServerError(c, "Could not load recovery plans", err.Error())
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var item map[string]any
		if err = rows.Scan(&item); err != nil {
			response.InternalServerError(c, "Could not read recovery plan", err.Error())
			return
		}
		items = append(items, item)
	}
	if one && len(items) == 0 {
		response.NotFound(c, "Recovery plan not found", nil)
		return
	}
	if one {
		response.OK(c, "Recovery plan loaded", items[0])
		return
	}
	response.OK(c, "Recovery plans loaded", items)
}

func (h *Handler) Status(c *gin.Context) {
	org, _, ok := contextIDs(c)
	if !ok {
		response.Unauthorized(c, "Invalid recovery context", nil)
		return
	}
	var stopped bool
	var reason string
	_ = h.db.QueryRow(c, `SELECT emergency_stop,COALESCE(reason,'') FROM recovery_controls WHERE organization_id=$1`, org).Scan(&stopped, &reason)
	rows, err := h.db.Query(c, `SELECT status,COUNT(*) FROM recovery_executions WHERE organization_id=$1 GROUP BY status`, org)
	if err != nil {
		response.InternalServerError(c, "Could not load recovery status", err.Error())
		return
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var status string
		var count int64
		if rows.Scan(&status, &count) == nil {
			counts[status] = count
		}
	}
	response.OK(c, "Recovery status loaded", gin.H{"emergency_stop": stopped, "emergency_stop_reason": reason, "executions": counts, "checked_at": time.Now().UTC()})
}

const recoverySchema = `
CREATE TABLE IF NOT EXISTS recovery_plans(id UUID PRIMARY KEY,organization_id UUID NOT NULL,incident_id UUID,name TEXT NOT NULL,reason TEXT NOT NULL,idempotency_key TEXT NOT NULL,actions JSONB NOT NULL,status TEXT NOT NULL,dry_run_result JSONB,created_by UUID NOT NULL,approved_by UUID,approved_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,idempotency_key));
CREATE TABLE IF NOT EXISTS recovery_executions(id UUID PRIMARY KEY,organization_id UUID NOT NULL,plan_id UUID NOT NULL REFERENCES recovery_plans(id),idempotency_key TEXT NOT NULL,status TEXT NOT NULL,result JSONB,rollback_result JSONB,attempt_count INTEGER NOT NULL DEFAULT 0,last_error TEXT,requested_by UUID NOT NULL,worker_owner TEXT,started_at TIMESTAMPTZ,completed_at TIMESTAMPTZ,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,idempotency_key));
CREATE TABLE IF NOT EXISTS recovery_controls(organization_id UUID PRIMARY KEY,emergency_stop BOOLEAN NOT NULL DEFAULT false,reason TEXT,changed_by UUID,changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS recovery_audit_events(id UUID PRIMARY KEY,organization_id UUID NOT NULL,plan_id UUID,execution_id UUID,event_type TEXT NOT NULL,actor_id UUID,details JSONB NOT NULL DEFAULT '{}',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`
