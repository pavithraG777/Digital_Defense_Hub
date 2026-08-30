package attribution

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"math"
	"strings"
	"time"
)

type Handler struct{ db *pgxpool.Pool }

func NewHandler() *Handler { return &Handler{} }

type Observation struct {
	Provider           string         `json:"provider"`
	SourceReference    string         `json:"source_reference"`
	IndicatorType      string         `json:"indicator_type"`
	IndicatorValue     string         `json:"indicator_value"`
	ASN                string         `json:"asn,omitempty"`
	CountryCode        string         `json:"country_code,omitempty"`
	Organization       string         `json:"organization,omitempty"`
	Association        string         `json:"association,omitempty"`
	Reputation         int            `json:"reputation"`
	ProviderConfidence int            `json:"provider_confidence"`
	FirstSeenAt        *time.Time     `json:"first_seen_at,omitempty"`
	LastSeenAt         time.Time      `json:"last_seen_at"`
	ExpiresAt          time.Time      `json:"expires_at"`
	Raw                map[string]any `json:"raw,omitempty"`
}
type Lead struct {
	Confidence             float64          `json:"confidence"`
	Level                  string           `json:"confidence_level"`
	PossibleInfrastructure []string         `json:"possible_infrastructure"`
	Associations           []string         `json:"associations"`
	Conflicts              []string         `json:"conflicting_evidence"`
	Provenance             []map[string]any `json:"provenance"`
	Explanation            []string         `json:"explanation"`
	HistoricalEventCount   int              `json:"historical_event_count"`
}

func RegisterRoutes(g *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if g == nil || h == nil || db == nil {
		return
	}
	h.db = db
	_ = ensure(context.Background(), db)
	r := g.Group("/attribution")
	r.POST("/observations", middleware.RequirePermission(db, "THREAT_ANALYSIS_EXECUTE"), h.RecordObservation)
	r.POST("/leads", middleware.RequirePermission(db, "THREAT_ANALYSIS_EXECUTE"), h.GenerateLead)
	r.GET("/leads", middleware.RequirePermission(db, "ATTRIBUTION_VIEW"), h.Leads)
	r.GET("/intel", middleware.RequirePermission(db, "ATTRIBUTION_VIEW"), h.Intel)
	r.PATCH("/leads/:id/disposition", middleware.RequirePermission(db, "THREAT_ANALYSIS_EXECUTE"), h.Disposition)
}
func ensure(ctx context.Context, db *pgxpool.Pool) error {
	_, e := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS attribution_observations(id UUID PRIMARY KEY,organization_id UUID NOT NULL,provider TEXT NOT NULL,source_reference TEXT NOT NULL,indicator_type TEXT NOT NULL,indicator_value TEXT NOT NULL,asn TEXT,country_code TEXT,network_organization TEXT,association TEXT,reputation INTEGER NOT NULL,provider_confidence INTEGER NOT NULL,first_seen_at TIMESTAMPTZ,last_seen_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,raw JSONB NOT NULL DEFAULT '{}',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,provider,source_reference,indicator_type,indicator_value));CREATE TABLE IF NOT EXISTS attribution_leads(id UUID PRIMARY KEY,organization_id UUID NOT NULL,indicator_type TEXT NOT NULL,indicator_value TEXT NOT NULL,confidence DOUBLE PRECISION NOT NULL,confidence_level TEXT NOT NULL,lead JSONB NOT NULL,model_version INTEGER NOT NULL,analyst_disposition TEXT,analyst_note TEXT,disposed_by UUID,disposed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`)
	return e
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
		return id, e == nil
	}
	return uuid.Nil, false
}
func normalize(kind, value string) string {
	kind = strings.ToUpper(strings.TrimSpace(kind))
	v := strings.ToLower(strings.TrimSpace(value))
	if kind == "DOMAIN" {
		v = strings.TrimSuffix(v, ".")
	}
	return v
}
func (h *Handler) RecordObservation(c *gin.Context) {
	org, ok := ctxID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q Observation
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid attribution observation", e.Error())
		return
	}
	q.Provider = strings.TrimSpace(q.Provider)
	q.IndicatorType = strings.ToUpper(strings.TrimSpace(q.IndicatorType))
	q.IndicatorValue = normalize(q.IndicatorType, q.IndicatorValue)
	if q.Provider == "" || q.SourceReference == "" || q.IndicatorValue == "" || q.ProviderConfidence < 0 || q.ProviderConfidence > 100 || q.Reputation < 0 || q.Reputation > 100 || q.LastSeenAt.IsZero() || q.ExpiresAt.IsZero() {
		response.BadRequest(c, "Observation provenance, confidence, freshness, and indicator are required", nil)
		return
	}
	id := uuid.New()
	e := h.db.QueryRow(c, `INSERT INTO attribution_observations(id,organization_id,provider,source_reference,indicator_type,indicator_value,asn,country_code,network_organization,association,reputation,provider_confidence,first_seen_at,last_seen_at,expires_at,raw)VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),$11,$12,$13,$14,$15,$16) ON CONFLICT(organization_id,provider,source_reference,indicator_type,indicator_value) DO UPDATE SET asn=EXCLUDED.asn,country_code=EXCLUDED.country_code,network_organization=EXCLUDED.network_organization,association=EXCLUDED.association,reputation=EXCLUDED.reputation,provider_confidence=EXCLUDED.provider_confidence,first_seen_at=EXCLUDED.first_seen_at,last_seen_at=EXCLUDED.last_seen_at,expires_at=EXCLUDED.expires_at,raw=EXCLUDED.raw RETURNING id`, id, org, q.Provider, q.SourceReference, q.IndicatorType, q.IndicatorValue, q.ASN, q.CountryCode, q.Organization, q.Association, q.Reputation, q.ProviderConfidence, q.FirstSeenAt, q.LastSeenAt, q.ExpiresAt, q.Raw).Scan(&id)
	if e != nil {
		response.InternalServerError(c, "Could not store attribution observation", e.Error())
		return
	}
	response.Created(c, "Attribution observation recorded", gin.H{"id": id, "observation": q})
}

type leadRequest struct {
	IndicatorType  string `json:"indicator_type" binding:"required"`
	IndicatorValue string `json:"indicator_value" binding:"required"`
}

func calculateLead(observations []Observation, historical int, now time.Time) Lead {
	lead := Lead{PossibleInfrastructure: []string{}, Associations: []string{}, Conflicts: []string{}, Provenance: []map[string]any{}, Explanation: []string{}, HistoricalEventCount: historical}
	weighted := 0.0
	countries := map[string]bool{}
	associations := map[string]bool{}
	infra := map[string]bool{}
	for _, o := range observations {
		fresh := 1.0
		if now.After(o.ExpiresAt) {
			fresh = .15
		} else {
			age := now.Sub(o.LastSeenAt).Hours() / 24
			if age > 30 {
				fresh = .5
			}
		}
		weighted += float64(o.Reputation) * (float64(o.ProviderConfidence) / 100) * fresh
		if o.CountryCode != "" {
			countries[o.CountryCode] = true
		}
		if o.Association != "" {
			associations[o.Association] = true
		}
		if o.ASN != "" {
			infra[o.ASN] = true
		}
		lead.Provenance = append(lead.Provenance, map[string]any{"provider": o.Provider, "source_reference": o.SourceReference, "last_seen_at": o.LastSeenAt, "expires_at": o.ExpiresAt, "provider_confidence": o.ProviderConfidence})
	}
	score := 0.0
	if len(observations) > 0 {
		score = weighted / float64(len(observations))
	}
	score += math.Min(10, float64(historical)*2)
	if len(countries) > 1 {
		lead.Conflicts = append(lead.Conflicts, "providers report different countries")
		score -= 10
	}
	if len(associations) > 1 {
		lead.Conflicts = append(lead.Conflicts, "providers report multiple possible associations")
		score -= 10
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	lead.Confidence = math.Round(score*100) / 100
	lead.Level = "LOW"
	if score >= 80 {
		lead.Level = "HIGH"
	} else if score >= 50 {
		lead.Level = "MEDIUM"
	}
	for v := range infra {
		lead.PossibleInfrastructure = append(lead.PossibleInfrastructure, v)
	}
	for v := range associations {
		lead.Associations = append(lead.Associations, v)
	}
	lead.Explanation = append(lead.Explanation, "confidence is weighted by provider confidence, reputation, freshness, conflicts, and tenant history")
	return lead
}
func (h *Handler) GenerateLead(c *gin.Context) {
	org, ok := ctxID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q leadRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid attribution lead request", e.Error())
		return
	}
	q.IndicatorType = strings.ToUpper(q.IndicatorType)
	q.IndicatorValue = normalize(q.IndicatorType, q.IndicatorValue)
	rows, e := h.db.Query(c, `SELECT provider,source_reference,indicator_type,indicator_value,COALESCE(asn,''),COALESCE(country_code,''),COALESCE(network_organization,''),COALESCE(association,''),reputation,provider_confidence,first_seen_at,last_seen_at,expires_at,raw FROM attribution_observations WHERE organization_id=$1 AND indicator_type=$2 AND indicator_value=$3`, org, q.IndicatorType, q.IndicatorValue)
	if e != nil {
		response.InternalServerError(c, "Could not load attribution observations", e.Error())
		return
	}
	observations := []Observation{}
	for rows.Next() {
		var o Observation
		if e = rows.Scan(&o.Provider, &o.SourceReference, &o.IndicatorType, &o.IndicatorValue, &o.ASN, &o.CountryCode, &o.Organization, &o.Association, &o.Reputation, &o.ProviderConfidence, &o.FirstSeenAt, &o.LastSeenAt, &o.ExpiresAt, &o.Raw); e != nil {
			rows.Close()
			response.InternalServerError(c, "Could not read attribution observation", e.Error())
			return
		}
		observations = append(observations, o)
	}
	rows.Close()
	if len(observations) == 0 {
		response.NotFound(c, "No attribution observations found", nil)
		return
	}
	var historical int
	_ = h.db.QueryRow(c, `SELECT COUNT(DISTINCT ee.event_id) FROM security_entities se JOIN security_event_entities ee ON ee.organization_id=se.organization_id AND ee.entity_id=se.id WHERE se.organization_id=$1 AND se.entity_type IN('IOC','IP') AND lower(se.entity_value)=$2`, org, q.IndicatorValue).Scan(&historical)
	lead := calculateLead(observations, historical, time.Now().UTC())
	id := uuid.New()
	_, e = h.db.Exec(c, `INSERT INTO attribution_leads(id,organization_id,indicator_type,indicator_value,confidence,confidence_level,lead,model_version)VALUES($1,$2,$3,$4,$5,$6,$7,1)`, id, org, q.IndicatorType, q.IndicatorValue, lead.Confidence, lead.Level, lead)
	if e != nil {
		response.InternalServerError(c, "Could not persist attribution lead", e.Error())
		return
	}
	response.Created(c, "Investigative attribution lead generated", gin.H{"id": id, "lead": lead, "disclaimer": "investigative assistance only; no actor identity is confirmed"})
}
func (h *Handler) Leads(c *gin.Context) {
	h.list(c, `SELECT jsonb_build_object('id',id,'indicator_type',indicator_type,'indicator_value',indicator_value,'confidence',confidence,'confidence_level',confidence_level,'lead',lead,'model_version',model_version,'analyst_disposition',analyst_disposition,'analyst_note',analyst_note,'created_at',created_at) FROM attribution_leads WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100`, "Attribution leads loaded")
}
func (h *Handler) Intel(c *gin.Context) {
	h.list(c, `SELECT jsonb_build_object('id',id,'provider',provider,'source_reference',source_reference,'indicator_type',indicator_type,'indicator_value',indicator_value,'asn',asn,'country_code',country_code,'association',association,'reputation',reputation,'provider_confidence',provider_confidence,'last_seen_at',last_seen_at,'expires_at',expires_at) FROM attribution_observations WHERE organization_id=$1 ORDER BY last_seen_at DESC LIMIT 200`, "Attribution intelligence loaded")
}
func (h *Handler) list(c *gin.Context, q, msg string) {
	org, ok := ctxID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	rows, e := h.db.Query(c, q, org)
	if e != nil {
		response.InternalServerError(c, "Could not load attribution data", e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var v map[string]any
		if e = rows.Scan(&v); e != nil {
			response.InternalServerError(c, "Could not read attribution data", e.Error())
			return
		}
		out = append(out, v)
	}
	response.OK(c, msg, out)
}

type dispositionRequest struct {
	Disposition string `json:"disposition" binding:"required,oneof=SUPPORTED INCONCLUSIVE REJECTED NEEDS_MORE_EVIDENCE"`
	Note        string `json:"note" binding:"required"`
}

func (h *Handler) Disposition(c *gin.Context) {
	org, ok := ctxID(c, "organization_id")
	actor, _ := ctxID(c, "user_id")
	id, e := uuid.Parse(c.Param("id"))
	if !ok || e != nil {
		response.BadRequest(c, "Invalid attribution context", nil)
		return
	}
	var q dispositionRequest
	if e = c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid analyst disposition", e.Error())
		return
	}
	tag, e := h.db.Exec(c, `UPDATE attribution_leads SET analyst_disposition=$3,analyst_note=$4,disposed_by=$5,disposed_at=NOW() WHERE organization_id=$1 AND id=$2`, org, id, q.Disposition, q.Note, actor)
	if e != nil {
		response.InternalServerError(c, "Could not save analyst disposition", e.Error())
		return
	}
	if tag.RowsAffected() != 1 {
		response.NotFound(c, "Attribution lead not found", nil)
		return
	}
	response.OK(c, "Analyst disposition recorded", gin.H{"id": id, "disposition": q.Disposition})
}
