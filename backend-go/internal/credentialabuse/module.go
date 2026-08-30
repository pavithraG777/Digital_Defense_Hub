package credentialabuse

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Handler struct{ repo *Repository }

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(g *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if g == nil || h == nil || db == nil {
		return
	}
	repo, e := NewRepository(db)
	if e != nil {
		return
	}
	_ = repo.EnsureSchema(context.Background())
	h.repo = repo
	r := g.Group("/credentialabuse")
	r.POST("/events", middleware.RequirePermission(db, "CREDENTIAL_ABUSE_MANAGE"), h.IngestEvent)
	r.GET("/events", middleware.RequirePermission(db, "CREDENTIAL_ABUSE_VIEW"), h.ListEvents)
	r.GET("/risks", middleware.RequirePermission(db, "CREDENTIAL_ABUSE_VIEW"), h.RiskSummary)
}
func org(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get("organization_id")
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

type ingest struct {
	UserID    uuid.UUID      `json:"user_id" binding:"required"`
	EventType string         `json:"event_type" binding:"required,oneof=FAILED_LOGIN PASSWORD_SPRAY IMPOSSIBLE_TRAVEL TOKEN_REPLAY CREDENTIAL_STUFFING MFA_FATIGUE SUCCESS_AFTER_FAILURES"`
	SourceIP  string         `json:"source_ip" binding:"required,ip"`
	DeviceID  string         `json:"device_id"`
	Count     int            `json:"count" binding:"min=1,max=100000"`
	Metadata  map[string]any `json:"metadata"`
}

func score(q ingest) (int, string) {
	s := 10
	switch q.EventType {
	case "TOKEN_REPLAY":
		s = 95
	case "IMPOSSIBLE_TRAVEL", "CREDENTIAL_STUFFING":
		s = 85
	case "PASSWORD_SPRAY", "MFA_FATIGUE":
		s = 75
	case "SUCCESS_AFTER_FAILURES":
		s = 65
	case "FAILED_LOGIN":
		s = 20 + q.Count*5
	}
	if s > 100 {
		s = 100
	}
	level := "LOW"
	if s >= 80 {
		level = "CRITICAL"
	} else if s >= 60 {
		level = "HIGH"
	} else if s >= 30 {
		level = "MEDIUM"
	}
	return s, level
}
func (h *Handler) IngestEvent(c *gin.Context) {
	organization, ok := org(c)
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q ingest
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid credential event", e.Error())
		return
	}
	s, l := score(q)
	if q.Metadata == nil {
		q.Metadata = map[string]any{}
	}
	q.Metadata["source_ip"] = q.SourceIP
	q.Metadata["device_id"] = q.DeviceID
	q.Metadata["count"] = q.Count
	q.Metadata["risk_score"] = s
	q.Metadata["risk_level"] = l
	e := &CredentialEvent{ID: uuid.New(), OrganizationID: organization, UserID: q.UserID, EventType: q.EventType, Metadata: q.Metadata, CreatedAt: time.Now().UTC()}
	if err := h.repo.CreateEvent(c, e, s, l); err != nil {
		response.InternalServerError(c, "Could not store credential event", err.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Credential event analyzed", gin.H{"event": e, "risk_score": s, "risk_level": l})
}
func (h *Handler) ListEvents(c *gin.Context) {
	organization, ok := org(c)
	if !ok {
		if h.repo == nil {
			c.JSON(200, gin.H{"success": true, "events": []any{}})
			return
		}
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit < 1 || limit > 200 {
		limit = 50
	}
	events, e := h.repo.ListEvents(c, organization, limit, 0)
	if e != nil {
		response.InternalServerError(c, "Could not list credential events", e.Error())
		return
	}
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	if q != "" {
		filtered := events[:0]
		for _, event := range events {
			if strings.Contains(strings.ToLower(event.EventType), q) {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}
	response.OK(c, "Credential events loaded", events)
}
func (h *Handler) RiskSummary(c *gin.Context) {
	organization, ok := org(c)
	if !ok {
		if h.repo == nil {
			c.JSON(200, gin.H{"success": true, "risk_summary": []any{}})
			return
		}
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	summary, e := h.repo.RiskSummary(c, organization)
	if e != nil {
		response.InternalServerError(c, "Could not calculate credential risk", e.Error())
		return
	}
	response.OK(c, "Credential risk summary loaded", summary)
}
