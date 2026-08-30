// Package intelligence exposes organization-scoped, read-optimized views for
// the SOC console. It never invents detections: every graph edge and score is
// derived from existing incident, threat, forensic, or mesh records.
package intelligence

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

func RegisterRoutes(group *gin.RouterGroup, db *pgxpool.Pool) {
	g := group.Group("/intelligence", middleware.RequirePermission(db, "DASHBOARD_VIEW"))
	g.GET("/dashboard", func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		data, err := dashboard(c, db, org)
		reply(c, "Organization intelligence dashboard retrieved", data, err)
	})
	g.GET("/threat-correlation", func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		data, err := correlation(c, db, org)
		reply(c, "Threat correlation graph retrieved", data, err)
	})
	g.GET("/threat-dna-radar", func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		data, err := dna(c, db, org)
		reply(c, "Threat DNA radar retrieved", data, err)
	})
	g.GET("/knowledge-graph", func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		data, err := knowledge(c, db, org)
		reply(c, "Knowledge graph retrieved", data, err)
	})
	g.GET("/attack-replay", func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		data, err := replay(c, db, org)
		reply(c, "Cyber attack replay retrieved", data, err)
	})
	g.GET("/deepfake-heatmap", func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		data, err := heatmap(c, db, org)
		reply(c, "Deepfake heatmap data retrieved", data, err)
	})
	g.GET("/ai-consensus", func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		data, err := consensus(c, db, org)
		reply(c, "AI consensus wheel data retrieved", data, err)
	})
	g.GET("/trust-evolution", func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		data, err := trust(c, db, org)
		reply(c, "Trust evolution graph data retrieved", data, err)
	})
	g.GET("/offline-mesh", func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		data, err := mesh(c, db, org)
		reply(c, "Offline intelligence mesh retrieved", data, err)
	})
	g.POST("/offline-mesh/nodes", middleware.RequirePermission(db, "ORGANIZATION_MANAGE_SECURITY"), func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		var r nodeRequest
		if c.ShouldBindJSON(&r) != nil || strings.TrimSpace(r.Name) == "" {
			response.BadRequest(c, "Invalid mesh node", nil)
			return
		}
		var id uuid.UUID
		err := db.QueryRow(c, `INSERT INTO intelligence_mesh_nodes (organization_id,node_name,node_type,connectivity_status,metadata,last_seen_at) VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP) ON CONFLICT (organization_id,node_name) DO UPDATE SET node_type=EXCLUDED.node_type,connectivity_status=EXCLUDED.connectivity_status,metadata=EXCLUDED.metadata,last_seen_at=CURRENT_TIMESTAMP RETURNING id`, org, strings.TrimSpace(r.Name), r.Type, r.Status, r.Metadata).Scan(&id)
		if err != nil {
			reply(c, "Unable to register mesh node", nil, err)
			return
		}
		response.Success(c, http.StatusCreated, "Mesh node registered", gin.H{"id": id})
	})
	g.POST("/offline-mesh/capsules", middleware.RequirePermission(db, "ORGANIZATION_MANAGE_SECURITY"), func(c *gin.Context) {
		org, ok := orgID(c)
		if !ok {
			return
		}
		var r capsuleRequest
		if c.ShouldBindJSON(&r) != nil || !json.Valid(r.Payload) {
			response.BadRequest(c, "Invalid intelligence capsule", nil)
			return
		}
		var id uuid.UUID
		err := db.QueryRow(c, `INSERT INTO intelligence_capsules (organization_id,source_node_id,target_node_id,capsule_type,payload,checksum_sha256,created_by) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7) RETURNING id`, org, r.Source, r.Target, r.Type, r.Payload, r.Checksum, userID(c)).Scan(&id)
		if err != nil {
			reply(c, "Unable to queue intelligence capsule", nil, err)
			return
		}
		_, err = db.Exec(c, `INSERT INTO offline_sync_queue (organization_id,sync_type,payload,checksum_sha256,created_by) VALUES ($1,'THREAT_INTELLIGENCE',$2,NULLIF($3,''),$4)`, org, r.Payload, r.Checksum, userID(c))
		if err != nil {
			reply(c, "Capsule queued but offline outbox update failed", nil, err)
			return
		}
		response.Success(c, http.StatusCreated, "Intelligence capsule queued for offline delivery", gin.H{"capsule_id": id, "status": "QUEUED"})
	})
}

type nodeRequest struct {
	Name     string          `json:"name"`
	Type     string          `json:"type" binding:"required,oneof=GOVERNMENT BUSINESS POLICE FORENSIC_LAB HOSPITAL BANK UNIVERSITY SOC EDGE"`
	Status   string          `json:"status" binding:"required,oneof=ONLINE OFFLINE DEGRADED"`
	Metadata json.RawMessage `json:"metadata"`
}
type capsuleRequest struct {
	Source   *uuid.UUID      `json:"source_node_id"`
	Target   *uuid.UUID      `json:"target_node_id"`
	Type     string          `json:"capsule_type" binding:"required,oneof=THREAT_INTELLIGENCE THREAT_DNA IOC CASE_REFERENCE MODEL_UPDATE"`
	Payload  json.RawMessage `json:"payload" binding:"required"`
	Checksum string          `json:"checksum_sha256" binding:"omitempty,len=64,hexadecimal"`
}

func orgID(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get("organization_id")
	id, valid := v.(uuid.UUID)
	if !ok || !valid || id == uuid.Nil {
		response.Unauthorized(c, "Organization authentication context is invalid", nil)
		return uuid.Nil, false
	}
	return id, true
}
func userID(c *gin.Context) any {
	v, ok := c.Get("user_id")
	if !ok {
		return nil
	}
	if id, ok := v.(uuid.UUID); ok && id != uuid.Nil {
		return id
	}
	return nil
}
func reply(c *gin.Context, msg string, data any, err error) {
	if err != nil {
		response.InternalServerError(c, msg, err.Error())
		return
	}
	response.Success(c, http.StatusOK, msg, data)
}
func dashboard(c *gin.Context, db *pgxpool.Pool, org uuid.UUID) (gin.H, error) {
	var incidents, threats, queue, review int
	err := db.QueryRow(c, `SELECT (SELECT count(*) FROM incidents WHERE organization_id=$1 AND deleted_at IS NULL AND status NOT IN ('CLOSED','RESOLVED')),(SELECT count(*) FROM threats WHERE organization_id=$1 AND deleted_at IS NULL AND status NOT IN ('RESOLVED','CLOSED')),(SELECT count(*) FROM offline_sync_queue WHERE organization_id=$1 AND status IN ('PENDING','IN_PROGRESS')),(SELECT count(*) FROM media_trust_assessments WHERE organization_id=$1 AND requires_human_review=true)`, org).Scan(&incidents, &threats, &queue, &review)
	return gin.H{"active_incidents": incidents, "active_threats": threats, "offline_queue": queue, "media_reviews": review, "generated_at": time.Now().UTC()}, err
}
func correlation(c *gin.Context, db *pgxpool.Pool, org uuid.UUID) (gin.H, error) {
	rows, err := db.Query(c, `SELECT i.id,i.incident_number,t.id,t.threat_code,t.threat_type,t.severity,it.relation_type FROM incident_threats it JOIN incidents i ON i.id=it.incident_id JOIN threats t ON t.id=it.threat_id WHERE i.organization_id=$1 AND i.deleted_at IS NULL AND t.deleted_at IS NULL ORDER BY i.created_at DESC LIMIT 250`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := []gin.H{}
	edges := []gin.H{}
	seen := map[string]bool{}
	for rows.Next() {
		var iid, tid uuid.UUID
		var ino, code, typ, sev, rel string
		if err = rows.Scan(&iid, &ino, &tid, &code, &typ, &sev, &rel); err != nil {
			return nil, err
		}
		if !seen[iid.String()] {
			nodes = append(nodes, gin.H{"id": iid, "kind": "INCIDENT", "label": ino})
			seen[iid.String()] = true
		}
		if !seen[tid.String()] {
			nodes = append(nodes, gin.H{"id": tid, "kind": "THREAT", "label": code, "threat_type": typ, "severity": sev})
			seen[tid.String()] = true
		}
		edges = append(edges, gin.H{"source": iid, "target": tid, "relation": rel})
	}
	return gin.H{"nodes": nodes, "edges": edges}, rows.Err()
}
func dna(c *gin.Context, db *pgxpool.Pool, org uuid.UUID) (gin.H, error) {
	rows, err := db.Query(c, `SELECT threat_type,count(*),max(severity) FROM threats WHERE organization_id=$1 AND deleted_at IS NULL GROUP BY threat_type ORDER BY count(*) DESC LIMIT 12`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	signals := []gin.H{}
	for rows.Next() {
		var kind, severity string
		var count int
		if err = rows.Scan(&kind, &count, &severity); err != nil {
			return nil, err
		}
		signals = append(signals, gin.H{"signal": kind, "count": count, "highest_severity": severity})
	}
	return gin.H{"signals": signals, "scale": "event_count"}, rows.Err()
}
func knowledge(c *gin.Context, db *pgxpool.Pool, org uuid.UUID) (gin.H, error) {
	return correlation(c, db, org)
}
func replay(c *gin.Context, db *pgxpool.Pool, org uuid.UUID) (gin.H, error) {
	id, err := uuid.Parse(strings.TrimSpace(c.Query("incident_id")))
	if err != nil || id == uuid.Nil {
		return nil, errInvalidID()
	}
	rows, err := db.Query(c, `SELECT event_type,title,description,metadata,occurred_at FROM incident_timeline WHERE organization_id=$1 AND incident_id=$2 ORDER BY occurred_at ASC LIMIT 500`, org, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []gin.H{}
	for rows.Next() {
		var typ, title string
		var desc *string
		var meta json.RawMessage
		var at time.Time
		if err = rows.Scan(&typ, &title, &desc, &meta, &at); err != nil {
			return nil, err
		}
		events = append(events, gin.H{"event_type": typ, "title": title, "description": desc, "metadata": meta, "occurred_at": at})
	}
	return gin.H{"incident_id": id, "events": events, "replay_safe": true}, rows.Err()
}
func heatmap(c *gin.Context, db *pgxpool.Pool, org uuid.UUID) (gin.H, error) {
	rows, err := db.Query(c, `SELECT media_asset_id,component_scores,risk_score,confidence_score,evaluated_at FROM media_trust_assessments WHERE organization_id=$1 ORDER BY evaluated_at DESC LIMIT 100`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var scores json.RawMessage
		var risk, confidence float64
		var at time.Time
		if err = rows.Scan(&id, &scores, &risk, &confidence, &at); err != nil {
			return nil, err
		}
		items = append(items, gin.H{"media_asset_id": id, "component_scores": scores, "risk_score": risk, "confidence_score": confidence, "evaluated_at": at})
	}
	return gin.H{"frames": items, "note": "Heatmap regions are supplied by forensic component scores; source media remains protected."}, rows.Err()
}
func consensus(c *gin.Context, db *pgxpool.Pool, org uuid.UUID) (gin.H, error) {
	var trust, risk, confidence float64
	var components json.RawMessage
	err := db.QueryRow(c, `SELECT trust_score,risk_score,confidence_score,component_scores FROM media_trust_assessments WHERE organization_id=$1 ORDER BY evaluated_at DESC LIMIT 1`, org).Scan(&trust, &risk, &confidence, &components)
	if err != nil {
		return gin.H{"available": false, "reason": "No completed media trust assessment"}, nil
	}
	return gin.H{"available": true, "trust_score": trust, "risk_score": risk, "confidence_score": confidence, "component_scores": components}, nil
}
func trust(c *gin.Context, db *pgxpool.Pool, org uuid.UUID) (gin.H, error) {
	rows, err := db.Query(c, `SELECT trust_score,risk_score,confidence_score,evaluated_at FROM media_trust_assessments WHERE organization_id=$1 ORDER BY evaluated_at ASC LIMIT 365`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	points := []gin.H{}
	for rows.Next() {
		var trust, risk, confidence float64
		var at time.Time
		if err = rows.Scan(&trust, &risk, &confidence, &at); err != nil {
			return nil, err
		}
		points = append(points, gin.H{"trust_score": trust, "risk_score": risk, "confidence_score": confidence, "evaluated_at": at})
	}
	return gin.H{"points": points}, rows.Err()
}
func mesh(c *gin.Context, db *pgxpool.Pool, org uuid.UUID) (gin.H, error) {
	rows, err := db.Query(c, `SELECT id,node_name,node_type,connectivity_status,last_seen_at,metadata FROM intelligence_mesh_nodes WHERE organization_id=$1 ORDER BY node_name`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var name, kind, status string
		var seen *time.Time
		var meta json.RawMessage
		if err = rows.Scan(&id, &name, &kind, &status, &seen, &meta); err != nil {
			return nil, err
		}
		nodes = append(nodes, gin.H{"id": id, "name": name, "type": kind, "status": status, "last_seen_at": seen, "metadata": meta})
	}
	return gin.H{"nodes": nodes, "mode": "offline_first"}, rows.Err()
}

type invalidIDError struct{}

func (invalidIDError) Error() string { return "incident_id must be a valid UUID" }
func errInvalidID() error            { return invalidIDError{} }
