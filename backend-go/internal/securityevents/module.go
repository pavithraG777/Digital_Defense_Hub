package securityevents

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

const CurrentSchemaVersion = 1

var allowedEntities = map[string]bool{"USER": true, "DEVICE": true, "SESSION": true, "IP": true, "PROCESS": true, "FILE": true, "CREDENTIAL": true, "NETWORK": true, "IOC": true, "INCIDENT": true}

type Entity struct {
	Type       string         `json:"type" binding:"required"`
	Value      string         `json:"value" binding:"required"`
	Attributes map[string]any `json:"attributes,omitempty"`
}
type IngestRequest struct {
	EventID        uuid.UUID       `json:"event_id" binding:"required"`
	IdempotencyKey string          `json:"idempotency_key" binding:"required,max=200"`
	Source         string          `json:"source" binding:"required,max=100"`
	EventType      string          `json:"event_type" binding:"required,max=100"`
	SchemaVersion  int             `json:"schema_version" binding:"required,min=1"`
	ObservedAt     time.Time       `json:"observed_at" binding:"required"`
	CorrelationID  *uuid.UUID      `json:"correlation_id"`
	Entities       []Entity        `json:"entities" binding:"required,min=1"`
	Payload        json.RawMessage `json:"payload" binding:"required"`
}
type Handler struct{ db *pgxpool.Pool }

func NewHandler(db *pgxpool.Pool) *Handler { return &Handler{db: db} }
func RegisterRoutes(g *gin.RouterGroup, db *pgxpool.Pool) {
	if g == nil || db == nil {
		return
	}
	h := NewHandler(db)
	r := g.Group("/security-events")
	r.POST("", middleware.RequirePermission(db, "ORGANIZATION_MANAGE_SECURITY"), h.Ingest)
	r.GET("", middleware.RequirePermission(db, "DASHBOARD_VIEW"), h.List)
	r.POST("/:id/replay", middleware.RequirePermission(db, "ORGANIZATION_MANAGE_SECURITY"), h.Replay)
	r.GET("/worker-health", middleware.RequirePermission(db, "DASHBOARD_VIEW"), h.WorkerHealth)
	r.GET("/dead-letters", middleware.RequirePermission(db, "ORGANIZATION_MANAGE_SECURITY"), h.DeadLetters)
	r.GET("/entity-graph", middleware.RequirePermission(db, "DASHBOARD_VIEW"), h.EntityGraph)
	r.GET("/correlations", middleware.RequirePermission(db, "DASHBOARD_VIEW"), h.Correlations)
	r.GET("/baselines", middleware.RequirePermission(db, "DASHBOARD_VIEW"), h.Baselines)
	r.GET("/detections", middleware.RequirePermission(db, "DASHBOARD_VIEW"), h.Detections)
	r.GET("/attack-stories", middleware.RequirePermission(db, "DASHBOARD_VIEW"), h.AttackStories)
}
func contextID(c *gin.Context, key string) (uuid.UUID, bool) {
	v, ok := c.Get(key)
	if !ok {
		return uuid.Nil, false
	}
	switch x := v.(type) {
	case uuid.UUID:
		return x, x != uuid.Nil
	case string:
		id, e := uuid.Parse(x)
		return id, e == nil && id != uuid.Nil
	}
	return uuid.Nil, false
}
func validate(q *IngestRequest) error {
	if q.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", q.SchemaVersion)
	}
	if !json.Valid(q.Payload) {
		return fmt.Errorf("payload must be valid JSON")
	}
	for i := range q.Entities {
		q.Entities[i].Type = strings.ToUpper(strings.TrimSpace(q.Entities[i].Type))
		q.Entities[i].Value = strings.TrimSpace(q.Entities[i].Value)
		if !allowedEntities[q.Entities[i].Type] || q.Entities[i].Value == "" {
			return fmt.Errorf("invalid entity at index %d", i)
		}
	}
	return nil
}
func (h *Handler) Ingest(c *gin.Context) {
	org, ok := contextID(c, "organization_id")
	actor, _ := contextID(c, "user_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q IngestRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid security event", e.Error())
		return
	}
	if e := validate(&q); e != nil {
		response.BadRequest(c, "Security event rejected", e.Error())
		return
	}
	canonical, _ := json.Marshal(struct {
		Source   string          `json:"source"`
		Type     string          `json:"type"`
		Observed time.Time       `json:"observed_at"`
		Entities []Entity        `json:"entities"`
		Payload  json.RawMessage `json:"payload"`
	}{q.Source, q.EventType, q.ObservedAt.UTC(), q.Entities, q.Payload})
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	tx, e := h.db.Begin(c)
	if e != nil {
		response.InternalServerError(c, "Could not start event transaction", e.Error())
		return
	}
	defer tx.Rollback(c)
	var id uuid.UUID
	var duplicate bool
	e = tx.QueryRow(c, `INSERT INTO normalized_security_events(id,organization_id,idempotency_key,source,event_type,schema_version,observed_at,correlation_id,raw_event_hash,payload,ingested_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(organization_id,idempotency_key) DO UPDATE SET duplicate_count=normalized_security_events.duplicate_count+1 RETURNING id,(xmax<>0)`, q.EventID, org, q.IdempotencyKey, q.Source, q.EventType, q.SchemaVersion, q.ObservedAt.UTC(), q.CorrelationID, digest, q.Payload, actor).Scan(&id, &duplicate)
	if e != nil {
		response.InternalServerError(c, "Could not persist security event", e.Error())
		return
	}
	if !duplicate {
		for _, entity := range q.Entities {
			var entityID uuid.UUID
			e = tx.QueryRow(c, `INSERT INTO security_entities(id,organization_id,entity_type,entity_value,attributes,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$6) ON CONFLICT(organization_id,entity_type,entity_value) DO UPDATE SET attributes=security_entities.attributes||EXCLUDED.attributes,last_seen_at=GREATEST(security_entities.last_seen_at,EXCLUDED.last_seen_at) RETURNING id`, uuid.New(), org, entity.Type, entity.Value, entity.Attributes, q.ObservedAt.UTC()).Scan(&entityID)
			if e != nil {
				response.InternalServerError(c, "Could not extract event entities", e.Error())
				return
			}
			_, e = tx.Exec(c, `INSERT INTO security_event_entities(event_id,entity_id,organization_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, id, entityID, org)
			if e != nil {
				response.InternalServerError(c, "Could not link event entity", e.Error())
				return
			}
		}
		envelope, _ := json.Marshal(gin.H{"event_id": id, "organization_id": org, "schema_version": q.SchemaVersion})
		_, e = tx.Exec(c, `INSERT INTO security_event_outbox(id,organization_id,event_id,topic,payload) VALUES($1,$2,$3,'security.event.normalized',$4)`, uuid.New(), org, id, envelope)
		if e != nil {
			response.InternalServerError(c, "Could not create event outbox record", e.Error())
			return
		}
	}
	if e = tx.Commit(c); e != nil {
		response.InternalServerError(c, "Could not commit security event", e.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Security event accepted", gin.H{"event_id": id, "duplicate": duplicate, "raw_event_hash": digest, "late": q.ObservedAt.Before(time.Now().UTC().Add(-5 * time.Minute))})
}
func (h *Handler) List(c *gin.Context) {
	org, ok := contextID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT id,source,event_type,schema_version,observed_at,ingested_at,correlation_id,raw_event_hash,duplicate_count,processing_status FROM normalized_security_events WHERE organization_id=$1 ORDER BY observed_at DESC,id DESC LIMIT 200`, org)
	if e != nil {
		response.InternalServerError(c, "Could not list security events", e.Error())
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var source, kind, hash, status string
		var version, duplicates int
		var observed, ingested time.Time
		var correlation *uuid.UUID
		if e = rows.Scan(&id, &source, &kind, &version, &observed, &ingested, &correlation, &hash, &duplicates, &status); e != nil {
			response.InternalServerError(c, "Could not read security event", e.Error())
			return
		}
		out = append(out, gin.H{"id": id, "source": source, "event_type": kind, "schema_version": version, "observed_at": observed, "ingested_at": ingested, "correlation_id": correlation, "raw_event_hash": hash, "duplicate_count": duplicates, "processing_status": status})
	}
	response.OK(c, "Security events loaded", out)
}
func (h *Handler) Replay(c *gin.Context) {
	org, ok := contextID(c, "organization_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid event context", nil)
		return
	}
	tx, e := h.db.Begin(c)
	if e != nil {
		response.InternalServerError(c, "Could not start replay", e.Error())
		return
	}
	defer tx.Rollback(c)
	var exists bool
	e = tx.QueryRow(c, `SELECT EXISTS(SELECT 1 FROM normalized_security_events WHERE organization_id=$1 AND id=$2)`, org, id).Scan(&exists)
	if e != nil || !exists {
		response.NotFound(c, "Security event not found", nil)
		return
	}
	payload, _ := json.Marshal(gin.H{"event_id": id, "organization_id": org, "replay": true})
	_, e = tx.Exec(c, `INSERT INTO security_event_outbox(id,organization_id,event_id,topic,payload)VALUES($1,$2,$3,'security.event.replay',$4)`, uuid.New(), org, id, payload)
	if e != nil {
		response.InternalServerError(c, "Could not queue replay", e.Error())
		return
	}
	_, _ = tx.Exec(c, `UPDATE normalized_security_events SET processing_status='PENDING' WHERE organization_id=$1 AND id=$2`, org, id)
	if e = tx.Commit(c); e != nil {
		response.InternalServerError(c, "Could not commit replay", e.Error())
		return
	}
	response.Accepted(c, "Security event replay queued", gin.H{"event_id": id})
}

func (h *Handler) WorkerHealth(c *gin.Context) {
	org, ok := contextID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var pending, processing, retry, dead int
	e := h.db.QueryRow(c, `SELECT COUNT(*) FILTER(WHERE status='PENDING'),COUNT(*) FILTER(WHERE status='PROCESSING'),COUNT(*) FILTER(WHERE status='RETRY'),COUNT(*) FILTER(WHERE status='DEAD_LETTER') FROM security_event_outbox WHERE organization_id=$1`, org).Scan(&pending, &processing, &retry, &dead)
	if e != nil {
		response.InternalServerError(c, "Could not load worker health", e.Error())
		return
	}
	response.OK(c, "Security event worker health loaded", gin.H{"pending": pending, "processing": processing, "retry": retry, "dead_letter": dead, "healthy": dead == 0})
}
func (h *Handler) DeadLetters(c *gin.Context) {
	org, ok := contextID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT id,event_id,outbox_id,reason,attempt_count,created_at,replayed_at FROM security_event_dead_letters WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100`, org)
	if e != nil {
		response.InternalServerError(c, "Could not list dead letters", e.Error())
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id, event uuid.UUID
		var outbox *uuid.UUID
		var reason string
		var attempts int
		var created time.Time
		var replayed *time.Time
		if e = rows.Scan(&id, &event, &outbox, &reason, &attempts, &created, &replayed); e != nil {
			response.InternalServerError(c, "Could not read dead letter", e.Error())
			return
		}
		out = append(out, gin.H{"id": id, "event_id": event, "outbox_id": outbox, "reason": reason, "attempt_count": attempts, "created_at": created, "replayed_at": replayed})
	}
	response.OK(c, "Security event dead letters loaded", out)
}

func (h *Handler) EntityGraph(c *gin.Context) {
	org, ok := contextID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT id,entity_type,entity_value,attributes,first_seen_at,last_seen_at FROM security_entities WHERE organization_id=$1 ORDER BY last_seen_at DESC LIMIT 500`, org)
	if e != nil {
		response.InternalServerError(c, "Could not load graph entities", e.Error())
		return
	}
	nodes := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var kind, value string
		var attrs map[string]any
		var first, last time.Time
		if e = rows.Scan(&id, &kind, &value, &attrs, &first, &last); e != nil {
			rows.Close()
			response.InternalServerError(c, "Could not read graph entity", e.Error())
			return
		}
		nodes = append(nodes, gin.H{"id": id, "type": kind, "value": value, "attributes": attrs, "first_seen_at": first, "last_seen_at": last})
	}
	rows.Close()
	edgesRows, e := h.db.Query(c, `SELECT source_entity_id,target_entity_id,relationship_type,first_seen_at,last_seen_at,event_count,confidence FROM security_entity_edges WHERE organization_id=$1 ORDER BY event_count DESC LIMIT 1000`, org)
	if e != nil {
		response.InternalServerError(c, "Could not load graph edges", e.Error())
		return
	}
	defer edgesRows.Close()
	edges := []gin.H{}
	for edgesRows.Next() {
		var source, target uuid.UUID
		var relationship string
		var first, last time.Time
		var count int
		var confidence float64
		if e = edgesRows.Scan(&source, &target, &relationship, &first, &last, &count, &confidence); e != nil {
			response.InternalServerError(c, "Could not read graph edge", e.Error())
			return
		}
		edges = append(edges, gin.H{"source": source, "target": target, "relationship": relationship, "first_seen_at": first, "last_seen_at": last, "event_count": count, "confidence": confidence})
	}
	response.OK(c, "Security entity graph loaded", gin.H{"nodes": nodes, "edges": edges})
}
func (h *Handler) Correlations(c *gin.Context) {
	org, ok := contextID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT id,rule_code,rule_version,severity,confidence,explanation,event_ids,entity_ids,first_observed_at,last_observed_at,created_at FROM security_correlation_findings WHERE organization_id=$1 ORDER BY last_observed_at DESC LIMIT 100`, org)
	if e != nil {
		response.InternalServerError(c, "Could not load correlations", e.Error())
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var rule, severity string
		var version int
		var confidence float64
		var explanation []string
		var events, entities []uuid.UUID
		var first, last, created time.Time
		if e = rows.Scan(&id, &rule, &version, &severity, &confidence, &explanation, &events, &entities, &first, &last, &created); e != nil {
			response.InternalServerError(c, "Could not read correlation", e.Error())
			return
		}
		out = append(out, gin.H{"id": id, "rule_code": rule, "rule_version": version, "severity": severity, "confidence": confidence, "explanation": explanation, "event_ids": events, "entity_ids": entities, "first_observed_at": first, "last_observed_at": last, "created_at": created})
	}
	response.OK(c, "Security correlations loaded", out)
}
func (h *Handler) Baselines(c *gin.Context) {
	org, ok := contextID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT metric,model_version,sample_count,mean,CASE WHEN sample_count>1 THEN sqrt(m2/(sample_count-1)) ELSE 0 END,last_observed_at FROM security_baseline_models WHERE organization_id=$1 ORDER BY metric`, org)
	if e != nil {
		response.InternalServerError(c, "Could not load baselines", e.Error())
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var metric string
		var version, count int
		var mean, stddev float64
		var last time.Time
		if e = rows.Scan(&metric, &version, &count, &mean, &stddev, &last); e != nil {
			response.InternalServerError(c, "Could not read baseline", e.Error())
			return
		}
		out = append(out, gin.H{"metric": metric, "model_version": version, "sample_count": count, "mean": mean, "stddev": stddev, "last_observed_at": last})
	}
	response.OK(c, "Security baselines loaded", out)
}
func (h *Handler) Detections(c *gin.Context) {
	h.listJSON(c, `SELECT jsonb_build_object('id',id,'event_id',event_id,'rule_code',rule_code,'rule_version',rule_version,'severity',severity,'risk_score',risk_score,'explanation',explanation,'observed_at',observed_at) FROM security_behavior_detections WHERE organization_id=$1 ORDER BY observed_at DESC LIMIT 100`, "Behavior detections loaded")
}
func (h *Handler) AttackStories(c *gin.Context) {
	h.listJSON(c, `SELECT jsonb_build_object('id',s.id,'title',s.title,'status',s.status,'current_version',s.current_version,'version',v.version,'timeline',v.timeline,'summary',v.summary,'updated_at',s.updated_at) FROM security_attack_stories s JOIN security_attack_story_versions v ON v.story_id=s.id AND v.version=s.current_version WHERE s.organization_id=$1 ORDER BY s.updated_at DESC`, "Attack stories loaded")
}
func (h *Handler) listJSON(c *gin.Context, q, msg string) {
	org, ok := contextID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, q, org)
	if e != nil {
		response.InternalServerError(c, "Could not load intelligence data", e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var value map[string]any
		if e = rows.Scan(&value); e != nil {
			response.InternalServerError(c, "Could not read intelligence data", e.Error())
			return
		}
		out = append(out, value)
	}
	response.OK(c, msg, out)
}

var _ = pgx.ErrNoRows
