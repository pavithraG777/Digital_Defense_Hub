package endpoint

import (
	"context"
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

type EndpointProtectionAssessment struct {
	RiskScore           int      `json:"risk_score"`
	RiskLevel           string   `json:"risk_level"`
	RequiresContainment bool     `json:"requires_containment"`
	RiskFlags           []string `json:"risk_flags"`
	Summary             string   `json:"summary"`
}

func ScoreEndpointProtectionRisk(id string, online, mfa, isolated bool) EndpointProtectionAssessment {
	flags := []string{}
	score := 0
	if strings.TrimSpace(id) == "" {
		flags = append(flags, "endpoint_identifier_missing")
		score += 20
	}
	if !online {
		flags = append(flags, "sensor_offline")
		score += 40
	}
	if !mfa {
		flags = append(flags, "mfa_not_enforced")
		score += 25
	}
	if isolated {
		flags = append(flags, "isolation_active")
		score -= 10
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	level := "LOW"
	contain := false
	if score >= 70 {
		level = "CRITICAL"
		contain = true
	} else if score >= 40 {
		level = "HIGH"
		contain = true
	} else if score > 0 {
		level = "MEDIUM"
	}
	summary := "endpoint posture is healthy"
	if contain {
		summary = "endpoint requires containment and analyst review"
	}
	return EndpointProtectionAssessment{score, level, contain, flags, summary}
}

type Handler struct{ db *pgxpool.Pool }

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(g *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if g == nil || h == nil || db == nil {
		return
	}
	h.db = db
	_ = ensureSchema(context.Background(), db)
	r := g.Group("/endpoints")
	r.GET("", middleware.RequirePermission(db, "ENDPOINT_VIEW"), h.ListEndpoints)
	r.GET("/:id", middleware.RequirePermission(db, "ENDPOINT_VIEW"), h.GetEndpoint)
	r.POST("/telemetry", middleware.RequirePermission(db, "ENDPOINT_SCAN"), h.IngestTelemetry)
	r.POST("/:id/scan", middleware.RequirePermission(db, "ENDPOINT_SCAN"), h.ScanEndpoint)
	r.POST("/:id/contain", middleware.RequirePermission(db, "ENDPOINT_CONTAIN"), h.ContainEndpoint)
	r.POST("/:id/release", middleware.RequirePermission(db, "ENDPOINT_CONTAIN"), h.ReleaseEndpoint)
}
func ensureSchema(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS endpoint_assets(id UUID PRIMARY KEY,organization_id UUID NOT NULL,external_id TEXT NOT NULL,hostname TEXT NOT NULL,platform TEXT NOT NULL DEFAULT 'UNKNOWN',sensor_online BOOLEAN NOT NULL DEFAULT TRUE,mfa_enforced BOOLEAN NOT NULL DEFAULT FALSE,isolation_active BOOLEAN NOT NULL DEFAULT FALSE,risk_score INTEGER NOT NULL DEFAULT 0,risk_level TEXT NOT NULL DEFAULT 'LOW',risk_flags JSONB NOT NULL DEFAULT '[]',last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,external_id));CREATE TABLE IF NOT EXISTS endpoint_actions(id UUID PRIMARY KEY,organization_id UUID NOT NULL,endpoint_id UUID NOT NULL,action_type TEXT NOT NULL,status TEXT NOT NULL,reason TEXT,requested_by UUID,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),completed_at TIMESTAMPTZ);`)
	return err
}
func ctxID(c *gin.Context, key string) (uuid.UUID, bool) {
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

type telemetryRequest struct {
	ExternalID   string `json:"external_id" binding:"required"`
	Hostname     string `json:"hostname" binding:"required"`
	Platform     string `json:"platform"`
	SensorOnline bool   `json:"sensor_online"`
	MFAEnforced  bool   `json:"mfa_enforced"`
}

func (h *Handler) IngestTelemetry(c *gin.Context) {
	org, ok := ctxID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q telemetryRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid endpoint telemetry", e.Error())
		return
	}
	a := ScoreEndpointProtectionRisk(q.ExternalID, q.SensorOnline, q.MFAEnforced, false)
	var id uuid.UUID
	e := h.db.QueryRow(c, `INSERT INTO endpoint_assets(id,organization_id,external_id,hostname,platform,sensor_online,mfa_enforced,risk_score,risk_level,risk_flags,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW()) ON CONFLICT(organization_id,external_id) DO UPDATE SET hostname=EXCLUDED.hostname,platform=EXCLUDED.platform,sensor_online=EXCLUDED.sensor_online,mfa_enforced=EXCLUDED.mfa_enforced,risk_score=EXCLUDED.risk_score,risk_level=EXCLUDED.risk_level,risk_flags=EXCLUDED.risk_flags,last_seen_at=NOW(),updated_at=NOW() RETURNING id`, uuid.New(), org, strings.TrimSpace(q.ExternalID), strings.TrimSpace(q.Hostname), strings.ToUpper(strings.TrimSpace(q.Platform)), q.SensorOnline, q.MFAEnforced, a.RiskScore, a.RiskLevel, a.RiskFlags).Scan(&id)
	if e != nil {
		response.InternalServerError(c, "Could not store endpoint telemetry", e.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Endpoint telemetry recorded", gin.H{"id": id, "assessment": a})
}
func (h *Handler) ListEndpoints(c *gin.Context) {
	org, ok := ctxID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT id,external_id,hostname,platform,sensor_online,mfa_enforced,isolation_active,risk_score,risk_level,risk_flags,last_seen_at FROM endpoint_assets WHERE organization_id=$1 ORDER BY risk_score DESC,last_seen_at DESC LIMIT 100`, org)
	if e != nil {
		response.InternalServerError(c, "Could not list endpoints", e.Error())
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var ext, host, platform, level string
		var online, mfa, isolated bool
		var score int
		var flags []string
		var seen time.Time
		if e = rows.Scan(&id, &ext, &host, &platform, &online, &mfa, &isolated, &score, &level, &flags, &seen); e != nil {
			response.InternalServerError(c, "Could not read endpoints", e.Error())
			return
		}
		out = append(out, gin.H{"id": id, "external_id": ext, "hostname": host, "platform": platform, "sensor_online": online, "mfa_enforced": mfa, "isolation_active": isolated, "risk_score": score, "risk_level": level, "risk_flags": flags, "last_seen_at": seen})
	}
	response.OK(c, "Endpoints loaded", out)
}
func (h *Handler) GetEndpoint(c *gin.Context) {
	org, ok := ctxID(c, "organization_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid endpoint context", nil)
		return
	}
	var out gin.H
	var ext, host, platform, level string
	var online, mfa, isolated bool
	var score int
	var flags []string
	var seen time.Time
	e = h.db.QueryRow(c, `SELECT external_id,hostname,platform,sensor_online,mfa_enforced,isolation_active,risk_score,risk_level,risk_flags,last_seen_at FROM endpoint_assets WHERE organization_id=$1 AND id=$2`, org, id).Scan(&ext, &host, &platform, &online, &mfa, &isolated, &score, &level, &flags, &seen)
	if e == pgx.ErrNoRows {
		response.NotFound(c, "Endpoint not found", nil)
		return
	}
	if e != nil {
		response.InternalServerError(c, "Could not load endpoint", e.Error())
		return
	}
	out = gin.H{"id": id, "external_id": ext, "hostname": host, "platform": platform, "sensor_online": online, "mfa_enforced": mfa, "isolation_active": isolated, "risk_score": score, "risk_level": level, "risk_flags": flags, "last_seen_at": seen}
	response.OK(c, "Endpoint loaded", out)
}

type actionRequest struct {
	Reason string `json:"reason" binding:"required"`
}

func (h *Handler) action(c *gin.Context, action string, isolated *bool) {
	org, ok := ctxID(c, "organization_id")
	actor, _ := ctxID(c, "user_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid endpoint context", nil)
		return
	}
	var q actionRequest
	if e = c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Action reason is required", e.Error())
		return
	}
	tx, e := h.db.Begin(c)
	if e != nil {
		response.InternalServerError(c, "Could not start endpoint action", e.Error())
		return
	}
	defer tx.Rollback(c)
	if isolated != nil {
		tag, e := tx.Exec(c, `UPDATE endpoint_assets SET isolation_active=$3,updated_at=NOW() WHERE organization_id=$1 AND id=$2`, org, id, *isolated)
		if e != nil || tag.RowsAffected() != 1 {
			response.NotFound(c, "Endpoint not found", nil)
			return
		}
	}
	var aid uuid.UUID
	e = tx.QueryRow(c, `INSERT INTO endpoint_actions(id,organization_id,endpoint_id,action_type,status,reason,requested_by,completed_at) VALUES($1,$2,$3,$4,'COMPLETED',$5,$6,NOW()) RETURNING id`, uuid.New(), org, id, action, strings.TrimSpace(q.Reason), actor).Scan(&aid)
	if e != nil {
		response.InternalServerError(c, "Could not record endpoint action", e.Error())
		return
	}
	if e = tx.Commit(c); e != nil {
		response.InternalServerError(c, "Could not complete endpoint action", e.Error())
		return
	}
	response.Accepted(c, "Endpoint action completed", gin.H{"action_id": aid, "endpoint_id": id, "action": action, "status": "COMPLETED"})
}
func (h *Handler) ScanEndpoint(c *gin.Context)    { h.action(c, "SCAN", nil) }
func (h *Handler) ContainEndpoint(c *gin.Context) { v := true; h.action(c, "CONTAIN", &v) }
func (h *Handler) ReleaseEndpoint(c *gin.Context) { v := false; h.action(c, "RELEASE", &v) }
