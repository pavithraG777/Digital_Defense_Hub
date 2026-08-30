package attackstory

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"net/http"
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
	_ = repo.BackfillAllOrganizations(context.Background())
	h.repo = repo
	r := g.Group("/attackstory")
	r.POST("", middleware.RequirePermission(db, "ATTACK_STORY_CREATE"), h.Create)
	r.GET("/timeline", middleware.RequirePermission(db, "ATTACK_STORY_VIEW"), h.Timeline)
	r.GET("/summary", middleware.RequirePermission(db, "ATTACK_STORY_VIEW"), h.Summary)
	r.GET("/mitre", middleware.RequirePermission(db, "ATTACK_STORY_VIEW"), h.MitreMapping)
}
func aid(c *gin.Context) (uuid.UUID, bool) {
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

type createRequest struct {
	Title    string           `json:"title" binding:"required"`
	Timeline []map[string]any `json:"timeline" binding:"required,min=1"`
}

func (h *Handler) Create(c *gin.Context) {
	org, ok := aid(c)
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	var q createRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		response.BadRequest(c, "Invalid attack story", e.Error())
		return
	}
	for i, event := range q.Timeline {
		if _, ok := event["timestamp"]; !ok {
			response.BadRequest(c, "Every timeline event requires timestamp", gin.H{"index": i})
			return
		}
	}
	story := &Story{ID: uuid.New(), OrganizationID: org, Title: strings.TrimSpace(q.Title), Timeline: q.Timeline, CreatedAt: time.Now().UTC()}
	if e := h.repo.CreateStory(c, story); e != nil {
		response.InternalServerError(c, "Could not create attack story", e.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Attack story created", story)
}
func (h *Handler) stories(c *gin.Context) ([]*Story, bool) {
	if h.repo == nil {
		return []*Story{}, true
	}
	org, ok := aid(c)
	if !ok {
		response.Unauthorized(c, "Invalid organization context", nil)
		return nil, false
	}
	if e := h.repo.BackfillOrganization(c, org); e != nil {
		response.InternalServerError(c, "Could not synchronize historical attack stories", e.Error())
		return nil, false
	}
	stories, e := h.repo.ListStories(c, org, 100, 0)
	if e != nil {
		response.InternalServerError(c, "Could not load attack stories", e.Error())
		return nil, false
	}
	return stories, true
}
func (h *Handler) Timeline(c *gin.Context) {
	stories, ok := h.stories(c)
	if !ok {
		return
	}
	events := []gin.H{}
	for _, s := range stories {
		for _, event := range s.Timeline {
			events = append(events, gin.H{"story_id": s.ID, "story_title": s.Title, "event": event})
		}
	}
	response.OK(c, "Attack timeline loaded", events)
}
func (h *Handler) Summary(c *gin.Context) {
	stories, ok := h.stories(c)
	if !ok {
		return
	}
	events, critical := 0, 0
	for _, s := range stories {
		events += len(s.Timeline)
		for _, event := range s.Timeline {
			if severity, ok := event["severity"].(string); ok && (strings.EqualFold(severity, "HIGH") || strings.EqualFold(severity, "CRITICAL")) {
				critical++
			}
		}
	}
	response.OK(c, "Attack story summary loaded", gin.H{"story_count": len(stories), "event_count": events, "high_or_critical_events": critical})
}
func (h *Handler) MitreMapping(c *gin.Context) {
	stories, ok := h.stories(c)
	if !ok {
		return
	}
	counts := map[string]int{}
	for _, s := range stories {
		for _, event := range s.Timeline {
			if technique, ok := event["mitre_technique"].(string); ok && strings.TrimSpace(technique) != "" {
				counts[technique]++
			}
		}
	}
	out := []gin.H{}
	for technique, count := range counts {
		out = append(out, gin.H{"technique": technique, "occurrences": count})
	}
	response.OK(c, "MITRE mapping loaded", out)
}
