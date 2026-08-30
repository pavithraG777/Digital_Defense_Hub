package lateralmovement

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
	r := g.Group("/lateralmovement")
	r.POST("/events", middleware.RequirePermission(db, "LATERAL_MOVEMENT_MANAGE"), h.Ingest)
	r.GET("/alerts", middleware.RequirePermission(db, "LATERAL_MOVEMENT_VIEW"), h.ListAlerts)
	r.GET("/graph", middleware.RequirePermission(db, "LATERAL_MOVEMENT_VIEW"), h.DeviceGraph)
}
func lid(c *gin.Context) (uuid.UUID, bool) {
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

type movement struct {
	SourceDevice       string         `json:"source_device" binding:"required"`
	TargetDevice       string         `json:"target_device" binding:"required"`
	Protocol           string         `json:"protocol" binding:"required"`
	AuthenticationType string         `json:"authentication_type"`
	NewPeer            bool           `json:"new_peer"`
	AdminShare         bool           `json:"admin_share"`
	RemoteExecution    bool           `json:"remote_execution"`
	FailedAttempts     int            `json:"failed_attempts" binding:"min=0"`
	Metadata           map[string]any `json:"metadata"`
}

func movementScore(q movement) (int, []string) {
	score := 0
	flags := []string{}
	if q.NewPeer {
		score += 25
		flags = append(flags, "new_peer")
	}
	if q.AdminShare {
		score += 30
		flags = append(flags, "admin_share")
	}
	if q.RemoteExecution {
		score += 40
		flags = append(flags, "remote_execution")
	}
	if q.FailedAttempts >= 5 {
		score += 20
		flags = append(flags, "repeated_authentication_failures")
	}
	if strings.EqualFold(q.AuthenticationType, "NTLM") {
		score += 10
		flags = append(flags, "legacy_authentication")
	}
	if score > 100 {
		score = 100
	}
	return score, flags
}
func (h *Handler) Ingest(c *gin.Context) {
	org, ok := lid(c)
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q movement
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid lateral movement event", e.Error())
		return
	}
	score, flags := movementScore(q)
	level := "LOW"
	if score >= 80 {
		level = "CRITICAL"
	} else if score >= 60 {
		level = "HIGH"
	} else if score >= 30 {
		level = "MEDIUM"
	}
	details := q.Metadata
	if details == nil {
		details = map[string]any{}
	}
	details["source_device"] = q.SourceDevice
	details["target_device"] = q.TargetDevice
	details["protocol"] = q.Protocol
	details["authentication_type"] = q.AuthenticationType
	details["risk_score"] = score
	details["risk_level"] = level
	details["risk_flags"] = flags
	a := &Alert{ID: uuid.New(), OrganizationID: org, DeviceID: q.SourceDevice, AlertType: "LATERAL_MOVEMENT", Details: details, CreatedAt: time.Now().UTC()}
	if e := h.repo.CreateAlert(c, a); e != nil {
		response.InternalServerError(c, "Could not persist lateral movement event", e.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Lateral movement event analyzed", gin.H{"alert": a, "risk_score": score, "risk_level": level, "risk_flags": flags})
}
func (h *Handler) ListAlerts(c *gin.Context) {
	org, ok := lid(c)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	if !ok {
		if h.repo == nil {
			c.JSON(200, gin.H{"success": true, "alerts": []any{}, "page": strconv.Itoa(page)})
			return
		}
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	alerts, e := h.repo.ListAlerts(c, org, 50, (page-1)*50)
	if e != nil {
		response.InternalServerError(c, "Could not list lateral movement alerts", e.Error())
		return
	}
	c.JSON(200, gin.H{"success": true, "alerts": alerts, "page": strconv.Itoa(page)})
}
func (h *Handler) DeviceGraph(c *gin.Context) {
	org, ok := lid(c)
	if !ok {
		if h.repo == nil {
			c.JSON(200, gin.H{"success": true, "graph": []any{}})
			return
		}
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	alerts, e := h.repo.ListAlerts(c, org, 500, 0)
	if e != nil {
		response.InternalServerError(c, "Could not build device graph", e.Error())
		return
	}
	nodes := map[string]int{}
	edges := map[string]gin.H{}
	for _, a := range alerts {
		src, _ := a.Details["source_device"].(string)
		dst, _ := a.Details["target_device"].(string)
		if src == "" {
			src = a.DeviceID
		}
		if src == "" || dst == "" {
			continue
		}
		nodes[src]++
		nodes[dst]++
		key := src + "\x00" + dst
		if edge, ok := edges[key]; ok {
			edge["count"] = edge["count"].(int) + 1
		} else {
			edges[key] = gin.H{"source": src, "target": dst, "count": 1, "last_seen_at": a.CreatedAt}
		}
	}
	nodeList := []gin.H{}
	for id, count := range nodes {
		nodeList = append(nodeList, gin.H{"id": id, "event_count": count})
	}
	edgeList := []gin.H{}
	for _, edge := range edges {
		edgeList = append(edgeList, edge)
	}
	response.OK(c, "Lateral movement graph loaded", gin.H{"nodes": nodeList, "edges": edgeList})
}
