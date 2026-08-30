package networksecurity

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"net/http"
	"strings"
	"time"
)

type NetworkSecurityAssessment struct {
	RiskScore          int      `json:"risk_score"`
	RiskLevel          string   `json:"risk_level"`
	RequiresQuarantine bool     `json:"requires_quarantine"`
	RiskFlags          []string `json:"risk_flags"`
	Summary            string   `json:"summary"`
}

func ScoreNetworkSecurityRisk(id string, online, visible, quarantined bool) NetworkSecurityAssessment {
	flags := []string{}
	score := 0
	if strings.TrimSpace(id) == "" {
		flags = append(flags, "sensor_identifier_missing")
		score += 20
	}
	if !online {
		flags = append(flags, "sensor_offline")
		score += 35
	}
	if !visible {
		flags = append(flags, "telemetry_visibility_reduced")
		score += 40
	}
	if quarantined {
		flags = append(flags, "network_quarantine_active")
		score -= 10
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	level := "LOW"
	q := false
	if score >= 70 {
		level = "CRITICAL"
		q = true
	} else if score >= 40 {
		level = "HIGH"
		q = true
	} else if score > 0 {
		level = "MEDIUM"
	}
	summary := "network telemetry posture is healthy"
	if q {
		summary = "network host requires quarantine and investigation"
	}
	return NetworkSecurityAssessment{score, level, q, flags, summary}
}

type Handler struct{ db *pgxpool.Pool }

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(g *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if g == nil || h == nil || db == nil {
		return
	}
	h.db = db
	_ = ensure(context.Background(), db)
	r := g.Group("/network-security")
	r.GET("/sensors", middleware.RequirePermission(db, "NETWORK_SECURITY_VIEW"), h.ListSensors)
	r.GET("/sensors/:id", middleware.RequirePermission(db, "NETWORK_SECURITY_VIEW"), h.GetSensor)
	r.POST("/telemetry", middleware.RequirePermission(db, "NETWORK_SECURITY_SCAN"), h.IngestTelemetry)
	r.GET("/flows", middleware.RequirePermission(db, "NETWORK_SECURITY_VIEW"), h.ListFlows)
	r.POST("/scan", middleware.RequirePermission(db, "NETWORK_SECURITY_SCAN"), h.StartScan)
	r.POST("/quarantine", middleware.RequirePermission(db, "NETWORK_SECURITY_QUARANTINE"), h.QuarantineHost)
}
func ensure(ctx context.Context, db *pgxpool.Pool) error {
	_, e := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS network_sensors(id UUID PRIMARY KEY,organization_id UUID NOT NULL,external_id TEXT NOT NULL,name TEXT NOT NULL,sensor_online BOOLEAN NOT NULL,visibility_healthy BOOLEAN NOT NULL,last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,external_id));CREATE TABLE IF NOT EXISTS network_flows(id UUID PRIMARY KEY,organization_id UUID NOT NULL,sensor_id UUID NOT NULL,source_ip INET NOT NULL,destination_ip INET NOT NULL,destination_port INTEGER NOT NULL,protocol TEXT NOT NULL,bytes_transferred BIGINT NOT NULL DEFAULT 0,quarantined BOOLEAN NOT NULL DEFAULT FALSE,risk_score INTEGER NOT NULL,risk_level TEXT NOT NULL,risk_flags JSONB NOT NULL DEFAULT '[]',observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW());CREATE TABLE IF NOT EXISTS network_actions(id UUID PRIMARY KEY,organization_id UUID NOT NULL,host_ip INET,action_type TEXT NOT NULL,status TEXT NOT NULL,reason TEXT,requested_by UUID,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`)
	return e
}
func cid(c *gin.Context, key string) (uuid.UUID, bool) {
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

type telemetry struct {
	SensorID          string `json:"sensor_id" binding:"required"`
	SensorName        string `json:"sensor_name" binding:"required"`
	SensorOnline      bool   `json:"sensor_online"`
	VisibilityHealthy bool   `json:"visibility_healthy"`
	SourceIP          string `json:"source_ip" binding:"required,ip"`
	DestinationIP     string `json:"destination_ip" binding:"required,ip"`
	DestinationPort   int    `json:"destination_port" binding:"required,min=1,max=65535"`
	Protocol          string `json:"protocol" binding:"required"`
	Bytes             int64  `json:"bytes_transferred" binding:"min=0"`
}

func (h *Handler) IngestTelemetry(c *gin.Context) {
	org, ok := cid(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q telemetry
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid network telemetry", e.Error())
		return
	}
	a := ScoreNetworkSecurityRisk(q.SensorID, q.SensorOnline, q.VisibilityHealthy, false)
	tx, e := h.db.Begin(c)
	if e != nil {
		response.InternalServerError(c, "Could not start telemetry transaction", e.Error())
		return
	}
	defer tx.Rollback(c)
	var sensor uuid.UUID
	e = tx.QueryRow(c, `INSERT INTO network_sensors(id,organization_id,external_id,name,sensor_online,visibility_healthy,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT(organization_id,external_id) DO UPDATE SET name=EXCLUDED.name,sensor_online=EXCLUDED.sensor_online,visibility_healthy=EXCLUDED.visibility_healthy,last_seen_at=NOW() RETURNING id`, uuid.New(), org, q.SensorID, q.SensorName, q.SensorOnline, q.VisibilityHealthy).Scan(&sensor)
	if e != nil {
		response.InternalServerError(c, "Could not store sensor", e.Error())
		return
	}
	var flow uuid.UUID
	e = tx.QueryRow(c, `INSERT INTO network_flows(id,organization_id,sensor_id,source_ip,destination_ip,destination_port,protocol,bytes_transferred,risk_score,risk_level,risk_flags) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`, uuid.New(), org, sensor, q.SourceIP, q.DestinationIP, q.DestinationPort, strings.ToUpper(q.Protocol), q.Bytes, a.RiskScore, a.RiskLevel, a.RiskFlags).Scan(&flow)
	if e != nil {
		response.InternalServerError(c, "Could not store flow", e.Error())
		return
	}
	if e = tx.Commit(c); e != nil {
		response.InternalServerError(c, "Could not commit telemetry", e.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Network telemetry recorded", gin.H{"sensor_id": sensor, "flow_id": flow, "assessment": a})
}
func (h *Handler) ListSensors(c *gin.Context) {
	org, ok := cid(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT id,external_id,name,sensor_online,visibility_healthy,last_seen_at FROM network_sensors WHERE organization_id=$1 ORDER BY last_seen_at DESC`, org)
	if e != nil {
		response.InternalServerError(c, "Could not list sensors", e.Error())
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var ext, name string
		var online, visible bool
		var seen time.Time
		if e = rows.Scan(&id, &ext, &name, &online, &visible, &seen); e != nil {
			response.InternalServerError(c, "Could not read sensor", e.Error())
			return
		}
		out = append(out, gin.H{"id": id, "external_id": ext, "name": name, "sensor_online": online, "visibility_healthy": visible, "last_seen_at": seen})
	}
	response.OK(c, "Network sensors loaded", out)
}
func (h *Handler) GetSensor(c *gin.Context) {
	org, ok := cid(c, "organization_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid sensor context", nil)
		return
	}
	var ext, name string
	var online, visible bool
	var seen time.Time
	e = h.db.QueryRow(c, `SELECT external_id,name,sensor_online,visibility_healthy,last_seen_at FROM network_sensors WHERE organization_id=$1 AND id=$2`, org, id).Scan(&ext, &name, &online, &visible, &seen)
	if e == pgx.ErrNoRows {
		response.NotFound(c, "Sensor not found", nil)
		return
	}
	if e != nil {
		response.InternalServerError(c, "Could not load sensor", e.Error())
		return
	}
	response.OK(c, "Network sensor loaded", gin.H{"id": id, "external_id": ext, "name": name, "sensor_online": online, "visibility_healthy": visible, "last_seen_at": seen})
}
func (h *Handler) ListFlows(c *gin.Context) {
	org, ok := cid(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT id,sensor_id,host(source_ip),host(destination_ip),destination_port,protocol,bytes_transferred,quarantined,risk_score,risk_level,risk_flags,observed_at FROM network_flows WHERE organization_id=$1 ORDER BY observed_at DESC LIMIT 200`, org)
	if e != nil {
		response.InternalServerError(c, "Could not list network flows", e.Error())
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id, sensor uuid.UUID
		var src, dst, proto, level string
		var port, score int
		var bytes int64
		var quarantined bool
		var flags []string
		var at time.Time
		if e = rows.Scan(&id, &sensor, &src, &dst, &port, &proto, &bytes, &quarantined, &score, &level, &flags, &at); e != nil {
			response.InternalServerError(c, "Could not read network flow", e.Error())
			return
		}
		out = append(out, gin.H{"id": id, "sensor_id": sensor, "source_ip": src, "destination_ip": dst, "destination_port": port, "protocol": proto, "bytes_transferred": bytes, "quarantined": quarantined, "risk_score": score, "risk_level": level, "risk_flags": flags, "observed_at": at})
	}
	response.OK(c, "Network flows loaded", out)
}

type action struct {
	HostIP string `json:"host_ip" binding:"required,ip"`
	Reason string `json:"reason" binding:"required"`
}

func (h *Handler) recordAction(c *gin.Context, kind string, quarantine bool) {
	org, ok := cid(c, "organization_id")
	actor, _ := cid(c, "user_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q action
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid network action", e.Error())
		return
	}
	tx, e := h.db.Begin(c)
	if e != nil {
		response.InternalServerError(c, "Could not start network action", e.Error())
		return
	}
	defer tx.Rollback(c)
	if quarantine {
		_, e = tx.Exec(c, `UPDATE network_flows SET quarantined=true WHERE organization_id=$1 AND (source_ip=$2 OR destination_ip=$2)`, org, q.HostIP)
		if e != nil {
			response.InternalServerError(c, "Could not quarantine host", e.Error())
			return
		}
	}
	id := uuid.New()
	_, e = tx.Exec(c, `INSERT INTO network_actions(id,organization_id,host_ip,action_type,status,reason,requested_by) VALUES($1,$2,$3,$4,'COMPLETED',$5,$6)`, id, org, q.HostIP, kind, q.Reason, actor)
	if e != nil {
		response.InternalServerError(c, "Could not record network action", e.Error())
		return
	}
	if e = tx.Commit(c); e != nil {
		response.InternalServerError(c, "Could not complete network action", e.Error())
		return
	}
	response.Accepted(c, "Network action completed", gin.H{"action_id": id, "status": "COMPLETED"})
}
func (h *Handler) StartScan(c *gin.Context)      { h.recordAction(c, "SCAN", false) }
func (h *Handler) QuarantineHost(c *gin.Context) { h.recordAction(c, "QUARANTINE", true) }
