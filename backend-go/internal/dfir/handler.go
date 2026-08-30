package dfir

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type Handler struct {
	service        *Service
	mlEngineURL    string
	mlServiceToken string
	mlTimeout      time.Duration
	httpClient     *http.Client
	worker         *Worker
}

func NewHandler(service *Service, mlCfg config.DFIRMLConfig) *Handler {
	client := &http.Client{Timeout: mlCfg.Timeout}
	return &Handler{
		service:        service,
		mlEngineURL:    mlCfg.EngineURL,
		mlServiceToken: mlCfg.ServiceToken,
		mlTimeout:      mlCfg.Timeout,
		httpClient:     client,
	}
}

func (h *Handler) SetWorker(w *Worker) {
	h.worker = w
}

func (h *Handler) Assess(c *gin.Context) {
	var req AssessmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid DFIR assessment request", err.Error())
		return
	}

	result := h.service.AssessRansomwareIndicators(req)
	response.OK(c, "DFIR ransomware assessment completed", result)
}

func (h *Handler) CreateIncident(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "DFIR handler is unavailable", nil)
		return
	}

	var payload struct {
		OrganizationID string   `json:"organization_id"`
		Title          string   `json:"title"`
		Signals        []string `json:"signals"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		response.BadRequest(c, "Invalid incident payload", err.Error())
		return
	}

	orgID, err := uuid.Parse(strings.TrimSpace(payload.OrganizationID))
	if err != nil || orgID == uuid.Nil {
		response.BadRequest(c, "Invalid organization_id", err.Error())
		return
	}

	incident, err := h.service.CreateIncident(orgID, payload.Title, payload.Signals)
	if err != nil {
		response.BadRequest(c, "Failed to create DFIR incident", err.Error())
		return
	}

	response.Created(c, "DFIR incident created", incident)
}

func (h *Handler) GetIncident(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "DFIR handler is unavailable", nil)
		return
	}

	incidentID, err := uuid.Parse(strings.TrimSpace(c.Param("id")))
	if err != nil || incidentID == uuid.Nil {
		response.BadRequest(c, "Invalid incident id", err.Error())
		return
	}

	summary := h.service.IncidentSummary(incidentID)
	if summary == nil {
		response.NotFound(c, "Incident not found", nil)
		return
	}

	evidence, err := h.service.ListEvidence(incidentID)
	if err != nil {
		response.InternalServerError(c, "Failed to load DFIR evidence", err.Error())
		return
	}

	timeline, err := h.service.ListTimeline(incidentID)
	if err != nil {
		response.InternalServerError(c, "Failed to load DFIR timeline", err.Error())
		return
	}

	response.OK(c, "DFIR incident retrieved", gin.H{
		"incident": summary,
		"evidence": evidence,
		"timeline": timeline,
	})
}

func (h *Handler) ListIncidents(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "DFIR handler is unavailable", nil)
		return
	}

	orgIDRaw := strings.TrimSpace(c.Query("organization_id"))
	if orgIDRaw == "" {
		orgIDRaw = strings.TrimSpace(c.Query("org_id"))
	}
	orgID, err := uuid.Parse(orgIDRaw)
	if err != nil || orgID == uuid.Nil {
		response.BadRequest(c, "Invalid organization_id", err.Error())
		return
	}

	incidents, err := h.service.ListIncidents(orgID)
	if err != nil {
		response.InternalServerError(c, "Failed to list DFIR incidents", err.Error())
		return
	}

	response.OK(c, "DFIR incidents retrieved", incidents)
}

func (h *Handler) ListIncidentEvidence(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "DFIR handler is unavailable", nil)
		return
	}

	incidentID, err := uuid.Parse(strings.TrimSpace(c.Param("id")))
	if err != nil || incidentID == uuid.Nil {
		response.BadRequest(c, "Invalid incident id", err.Error())
		return
	}

	evidence, err := h.service.ListEvidence(incidentID)
	if err != nil {
		response.InternalServerError(c, "Failed to list DFIR evidence", err.Error())
		return
	}

	response.OK(c, "DFIR evidence retrieved", evidence)
}

func (h *Handler) ListIncidentTimeline(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "DFIR handler is unavailable", nil)
		return
	}

	incidentID, err := uuid.Parse(strings.TrimSpace(c.Param("id")))
	if err != nil || incidentID == uuid.Nil {
		response.BadRequest(c, "Invalid incident id", err.Error())
		return
	}

	timeline, err := h.service.ListTimeline(incidentID)
	if err != nil {
		response.InternalServerError(c, "Failed to list DFIR timeline", err.Error())
		return
	}

	response.OK(c, "DFIR timeline retrieved", timeline)
}

func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "DFIR module is ready",
		"data": gin.H{
			"status": "ok",
		},
	})
}

// ProxyML forwards the incoming JSON payload to the external ML service and
// returns its JSON response. Requires ML engine URL to be configured.
func (h *Handler) ProxyML(c *gin.Context) {
	if h == nil || h.httpClient == nil || h.mlEngineURL == "" {
		response.InternalServerError(c, "ML engine is not configured", nil)
		return
	}

	// quick readiness check before proxying
	healthCtx, healthCancel := context.WithTimeout(c.Request.Context(), 1*time.Second)
	defer healthCancel()
	if !h.mlIsHealthy(healthCtx) {
		response.InternalServerError(c, "ML engine is not healthy", nil)
		return
	}

	var payload map[string]interface{}
	if err := c.ShouldBindJSON(&payload); err != nil {
		response.BadRequest(c, "Invalid ML payload", err.Error())
		return
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		response.InternalServerError(c, "failed to marshal payload", err.Error())
		return
	}

	reqCtx, cancel := context.WithTimeout(c.Request.Context(), h.mlTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, h.mlEngineURL+"/score", bytes.NewReader(bodyBytes))
	if err != nil {
		response.InternalServerError(c, "failed to create ML request", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if h.mlServiceToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.mlServiceToken)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		response.InternalServerError(c, "ML service request failed", err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		response.InternalServerError(c, "failed to read ML response", err.Error())
		return
	}

	// Pass through status and body
	c.Data(resp.StatusCode, "application/json", respBody)
}

// mlIsHealthy performs a simple GET /health against the configured ML engine
// and returns true if the engine responds with a 2xx status within the
// provided context deadline.
func (h *Handler) mlIsHealthy(ctx context.Context) bool {
	if h == nil || h.mlEngineURL == "" {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.mlEngineURL+"/health", nil)
	if err != nil {
		return false
	}
	if h.mlServiceToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.mlServiceToken)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil || resp == nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// ExtractAndScore accepts raw event payloads, extracts features, calls the ML
// engine, and returns a combined rule-based and ML result.
func (h *Handler) ExtractAndScore(c *gin.Context) {
	if h == nil {
		response.InternalServerError(c, "DFIR handler is unavailable", nil)
		return
	}

	var event map[string]interface{}
	if err := c.ShouldBindJSON(&event); err != nil {
		response.BadRequest(c, "Invalid event payload", err.Error())
		return
	}

	// Derive signals for rule-based scoring
	signals := inferSignalsFromEvent(event)
	req := AssessmentRequest{
		Signals:       signals,
		EvidenceCount: intValue(event["evidence_count"]),
	}

	ruleResult := h.service.AssessRansomwareIndicators(req)

	// Build ML features
	features := buildFeaturePayloadFromEvent(event)

	// Call ML service if configured
	mlResult := map[string]interface{}{"available": false}
	if h.mlEngineURL != "" {
		// check health first (short timeout)
		healthCtx, healthCancel := context.WithTimeout(c.Request.Context(), 1*time.Second)
		defer healthCancel()
		if !h.mlIsHealthy(healthCtx) {
			// ML not available; respond with available=false
			combined := gin.H{
				"rule": ruleResult,
				"ml":   mlResult,
			}
			response.OK(c, "Feature extraction and scoring result", combined)
			return
		}
		bodyBytes, _ := json.Marshal(features)
		reqCtx, cancel := context.WithTimeout(c.Request.Context(), h.mlTimeout)
		defer cancel()
		mlReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, h.mlEngineURL+"/score", bytes.NewReader(bodyBytes))
		if err == nil {
			mlReq.Header.Set("Content-Type", "application/json")
			if h.mlServiceToken != "" {
				mlReq.Header.Set("Authorization", "Bearer "+h.mlServiceToken)
			}
			resp, err := h.httpClient.Do(mlReq)
			if err == nil && resp != nil {
				defer resp.Body.Close()
				respBody, err := io.ReadAll(resp.Body)
				if err == nil {
					_ = json.Unmarshal(respBody, &mlResult)
				}
			}
		}
	}

	combined := gin.H{
		"rule": ruleResult,
		"ml":   mlResult,
	}
	response.OK(c, "Feature extraction and scoring result", combined)
}

func intValue(v interface{}) int {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case string:
		// try parse
		return 0
	default:
		return 0
	}
}

// EnqueueEvent accepts an event and pushes it to the DFIR worker queue for
// asynchronous processing.
func (h *Handler) EnqueueEvent(c *gin.Context) {
	if h.worker == nil {
		response.InternalServerError(c, "ingest worker is unavailable", nil)
		return
	}

	var event map[string]interface{}
	if err := c.ShouldBindJSON(&event); err != nil {
		response.BadRequest(c, "invalid event payload", err.Error())
		return
	}

	if err := h.worker.Enqueue(event); err != nil {
		response.InternalServerError(c, "failed to enqueue event", err.Error())
		return
	}

	response.OK(c, "event enqueued", nil)
}
