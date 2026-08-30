package threatintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Handler struct{ db *pgxpool.Pool }

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(g *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if g == nil || h == nil || db == nil {
		return
	}
	h.db = db
	_ = schema(context.Background(), db)
	r := g.Group("/threat-intelligence")
	r.POST("/enrich", middleware.RequirePermission(db, "THREAT_ANALYSIS_EXECUTE"), h.EnrichIndicator)
	r.POST("/enrich/provider", middleware.RequirePermission(db, "THREAT_ANALYSIS_EXECUTE"), h.QueueProviderEnrichment)
	r.GET("/jobs", middleware.RequirePermission(db, "THREAT_ANALYSIS_VIEW"), h.ListJobs)
	r.GET("/indicators", middleware.RequirePermission(db, "THREAT_ANALYSIS_VIEW"), h.ListIndicators)
	r.GET("/indicators/:id", middleware.RequirePermission(db, "THREAT_ANALYSIS_VIEW"), h.GetIndicator)
	r.POST("/indicators/:id/review", middleware.RequirePermission(db, "THREAT_ANALYSIS_EXECUTE"), h.ReviewIndicator)
}
func schema(ctx context.Context, db *pgxpool.Pool) error {
	_, e := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS threat_intelligence_indicators(id UUID PRIMARY KEY,organization_id UUID NOT NULL,indicator_type TEXT NOT NULL,indicator_value TEXT NOT NULL,normalized_value TEXT NOT NULL,reputation_score INTEGER NOT NULL,confidence INTEGER NOT NULL,severity TEXT NOT NULL,tags JSONB NOT NULL DEFAULT '[]',sources JSONB NOT NULL DEFAULT '[]',first_seen_at TIMESTAMPTZ NOT NULL,last_seen_at TIMESTAMPTZ NOT NULL,status TEXT NOT NULL DEFAULT 'ACTIVE',reviewed_by UUID,reviewed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,indicator_type,normalized_value));`)
	return e
}
func ids(c *gin.Context, key string) (uuid.UUID, bool) {
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

type source struct {
	Name       string   `json:"name" binding:"required"`
	Reputation int      `json:"reputation" binding:"min=0,max=100"`
	Confidence int      `json:"confidence" binding:"min=0,max=100"`
	Tags       []string `json:"tags"`
}
type enrichRequest struct {
	Type    string   `json:"type" binding:"required,oneof=IP DOMAIN URL SHA256 EMAIL"`
	Value   string   `json:"value" binding:"required"`
	Sources []source `json:"sources" binding:"required,min=1"`
}

func normalize(kind, value string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	switch kind {
	case "IP":
		if net.ParseIP(v) == nil {
			return "", &url.Error{Op: "validate", URL: v, Err: net.InvalidAddrError("invalid IP")}
		}
	case "DOMAIN":
		v = strings.TrimSuffix(v, ".")
		if !strings.Contains(v, ".") {
			return "", net.InvalidAddrError("invalid domain")
		}
	case "URL":
		u, e := url.ParseRequestURI(v)
		if e != nil || u.Host == "" {
			return "", net.InvalidAddrError("invalid URL")
		}
		v = u.String()
	case "SHA256":
		raw, e := hex.DecodeString(v)
		if e != nil || len(raw) != sha256.Size {
			return "", net.InvalidAddrError("invalid SHA-256")
		}
	case "EMAIL":
		if !strings.Contains(v, "@") {
			return "", net.InvalidAddrError("invalid email")
		}
	}
	return v, nil
}
func (h *Handler) EnrichIndicator(c *gin.Context) {
	org, ok := ids(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q enrichRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid enrichment request", e.Error())
		return
	}
	kind := strings.ToUpper(q.Type)
	normalized, e := normalize(kind, q.Value)
	if e != nil {
		response.BadRequest(c, "Invalid indicator", e.Error())
		return
	}
	total, confidence := 0, 0
	tags := []string{}
	for _, s := range q.Sources {
		total += s.Reputation * s.Confidence
		confidence += s.Confidence
		tags = append(tags, s.Tags...)
	}
	score := 0
	if confidence > 0 {
		score = total / confidence
	}
	avgConfidence := confidence / len(q.Sources)
	severity := "LOW"
	if score >= 80 {
		severity = "CRITICAL"
	} else if score >= 60 {
		severity = "HIGH"
	} else if score >= 30 {
		severity = "MEDIUM"
	}
	now := time.Now().UTC()
	var id uuid.UUID
	e = h.db.QueryRow(c, `INSERT INTO threat_intelligence_indicators(id,organization_id,indicator_type,indicator_value,normalized_value,reputation_score,confidence,severity,tags,sources,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11) ON CONFLICT(organization_id,indicator_type,normalized_value) DO UPDATE SET indicator_value=EXCLUDED.indicator_value,reputation_score=EXCLUDED.reputation_score,confidence=EXCLUDED.confidence,severity=EXCLUDED.severity,tags=EXCLUDED.tags,sources=EXCLUDED.sources,last_seen_at=EXCLUDED.last_seen_at,updated_at=NOW() RETURNING id`, uuid.New(), org, kind, strings.TrimSpace(q.Value), normalized, score, avgConfidence, severity, tags, q.Sources, now).Scan(&id)
	if e != nil {
		response.InternalServerError(c, "Could not persist enrichment", e.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Threat indicator enriched", gin.H{"id": id, "type": kind, "normalized_value": normalized, "reputation_score": score, "confidence": avgConfidence, "severity": severity, "sources": q.Sources, "tags": tags})
}
func (h *Handler) ListIndicators(c *gin.Context) {
	org, ok := ids(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT id,indicator_type,indicator_value,reputation_score,confidence,severity,tags,sources,status,first_seen_at,last_seen_at FROM threat_intelligence_indicators WHERE organization_id=$1 ORDER BY reputation_score DESC,last_seen_at DESC LIMIT 200`, org)
	if e != nil {
		response.InternalServerError(c, "Could not list indicators", e.Error())
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id uuid.UUID
		var kind, value, severity, status string
		var score, confidence int
		var tags []string
		var sources []source
		var first, last time.Time
		if e = rows.Scan(&id, &kind, &value, &score, &confidence, &severity, &tags, &sources, &status, &first, &last); e != nil {
			response.InternalServerError(c, "Could not read indicator", e.Error())
			return
		}
		out = append(out, gin.H{"id": id, "type": kind, "value": value, "reputation_score": score, "confidence": confidence, "severity": severity, "tags": tags, "sources": sources, "status": status, "first_seen_at": first, "last_seen_at": last})
	}
	response.OK(c, "Threat indicators loaded", out)
}
func (h *Handler) GetIndicator(c *gin.Context) {
	org, ok := ids(c, "organization_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid indicator context", nil)
		return
	}
	var kind, value, severity, status string
	var score, confidence int
	var tags []string
	var sources []source
	var first, last time.Time
	e = h.db.QueryRow(c, `SELECT indicator_type,indicator_value,reputation_score,confidence,severity,tags,sources,status,first_seen_at,last_seen_at FROM threat_intelligence_indicators WHERE organization_id=$1 AND id=$2`, org, id).Scan(&kind, &value, &score, &confidence, &severity, &tags, &sources, &status, &first, &last)
	if e != nil {
		response.NotFound(c, "Indicator not found", nil)
		return
	}
	response.OK(c, "Threat indicator loaded", gin.H{"id": id, "type": kind, "value": value, "reputation_score": score, "confidence": confidence, "severity": severity, "tags": tags, "sources": sources, "status": status, "first_seen_at": first, "last_seen_at": last})
}

type review struct {
	Status string `json:"status" binding:"required,oneof=ACTIVE FALSE_POSITIVE REVOKED"`
}

func (h *Handler) ReviewIndicator(c *gin.Context) {
	org, ok := ids(c, "organization_id")
	actor, _ := ids(c, "user_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid indicator context", nil)
		return
	}
	var q review
	if e = c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid review", e.Error())
		return
	}
	tag, e := h.db.Exec(c, `UPDATE threat_intelligence_indicators SET status=$3,reviewed_by=$4,reviewed_at=NOW(),updated_at=NOW() WHERE organization_id=$1 AND id=$2`, org, id, q.Status, actor)
	if e != nil {
		response.InternalServerError(c, "Could not review indicator", e.Error())
		return
	}
	if tag.RowsAffected() != 1 {
		response.NotFound(c, "Indicator not found", nil)
		return
	}
	response.OK(c, "Threat indicator reviewed", gin.H{"id": id, "status": q.Status})
}

type providerRequest struct {
	Type           string `json:"type" binding:"required,oneof=IP DOMAIN URL SHA256 EMAIL"`
	Value          string `json:"value" binding:"required"`
	IdempotencyKey string `json:"idempotency_key" binding:"required,max=200"`
}

func (h *Handler) QueueProviderEnrichment(c *gin.Context) {
	org, ok := ids(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q providerRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid provider enrichment request", e.Error())
		return
	}
	kind := strings.ToUpper(q.Type)
	normalized, e := normalize(kind, q.Value)
	if e != nil {
		response.BadRequest(c, "Invalid indicator", e.Error())
		return
	}
	id := uuid.New()
	e = h.db.QueryRow(c, `INSERT INTO threat_intelligence_jobs(id,organization_id,indicator_type,indicator_value,normalized_value,idempotency_key,status) VALUES($1,$2,$3,$4,$5,$6,'QUEUED') ON CONFLICT(organization_id,idempotency_key) DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key RETURNING id`, id, org, kind, q.Value, normalized, q.IdempotencyKey).Scan(&id)
	if e != nil {
		response.InternalServerError(c, "Could not queue provider enrichment", e.Error())
		return
	}
	response.Accepted(c, "Provider enrichment queued", gin.H{"job_id": id, "status": "QUEUED"})
}

func (h *Handler) ListJobs(c *gin.Context) {
	org, ok := ids(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, `SELECT jsonb_build_object('id',id,'indicator_type',indicator_type,'indicator_value',indicator_value,'status',status,'attempt_count',attempt_count,'last_error',last_error,'created_at',created_at,'completed_at',completed_at) FROM threat_intelligence_jobs WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100`, org)
	if e != nil {
		response.InternalServerError(c, "Could not load enrichment jobs", e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var item map[string]any
		if e = rows.Scan(&item); e != nil {
			response.InternalServerError(c, "Could not read enrichment job", e.Error())
			return
		}
		out = append(out, item)
	}
	response.OK(c, "Provider enrichment jobs loaded", out)
}
