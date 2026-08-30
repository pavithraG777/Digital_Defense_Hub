package dfir

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
)

func TestExtractAndScoreSkipsMLWhenHealthFails(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mlServer.Close()

	service := NewService()
	h := NewHandler(service, config.DFIRMLConfig{EngineURL: mlServer.URL, Timeout: 1 * time.Second})

	r := gin.New()
	r.POST("/api/v1/dfir/feature/score", h.ExtractAndScore)

	ts := httptest.NewServer(r)
	defer ts.Close()

	payload := map[string]interface{}{
		"file_event_rate": 1.0,
		"rename_rate":     0.5,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(ts.URL+"/api/v1/dfir/feature/score", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["message"] != "Feature extraction and scoring result" {
		t.Fatalf("unexpected message: %v", result["message"])
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data object, got %T", result["data"])
	}

	ml, ok := data["ml"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected ml object, got %T", data["ml"])
	}

	if available, exists := ml["available"].(bool); !exists || available {
		t.Fatalf("expected ml.available=false when health fails, got %v", ml["available"])
	}
}

func TestProxyMLReturnsScoreWhenHealthy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"healthy":true}`))
		case "/score":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success":true,"probability":0.78}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mlServer.Close()

	service := NewService()
	h := NewHandler(service, config.DFIRMLConfig{EngineURL: mlServer.URL, Timeout: 1 * time.Second})

	r := gin.New()
	r.POST("/api/v1/dfir/ml/score", h.ProxyML)

	ts := httptest.NewServer(r)
	defer ts.Close()

	payload := map[string]interface{}{
		"file_event_rate": 1.0,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(ts.URL+"/api/v1/dfir/ml/score", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if success, ok := result["success"].(bool); !ok || !success {
		t.Fatalf("expected success=true, got %v", result["success"])
	}

	if _, ok := result["probability"]; !ok {
		t.Fatalf("expected probability in response")
	}
}

func TestCreateAndFetchIncident(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := NewService()
	h := NewHandler(service, config.DFIRMLConfig{Timeout: 1 * time.Second})

	r := gin.New()
	r.POST("/api/v1/dfir/incidents", h.CreateIncident)
	r.GET("/api/v1/dfir/incidents/:id", h.GetIncident)
	r.GET("/api/v1/dfir/incidents/:id/evidence", h.ListIncidentEvidence)
	r.GET("/api/v1/dfir/incidents/:id/timeline", h.ListIncidentTimeline)

	ts := httptest.NewServer(r)
	defer ts.Close()

	payload := map[string]interface{}{
		"organization_id": uuid.New().String(),
		"title":           "Finance endpoint encryption activity",
		"signals":         []string{"canary_access", "rapid_file_encryption", "shadow_copy_deletion"},
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(ts.URL+"/api/v1/dfir/incidents", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
	}

	var created map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	data, ok := created["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data object in response, got %#v", created["data"])
	}

	incidentID, ok := data["id"].(string)
	if !ok || incidentID == "" {
		t.Fatalf("expected incident id in response, got %#v", data["id"])
	}

	resp2, err := http.Get(ts.URL + "/api/v1/dfir/incidents/" + incidentID)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on fetch, got %d", resp2.StatusCode)
	}

	_, err = service.AddEvidence(uuid.MustParse(incidentID), "file", "finance-server", "abc123")
	if err != nil {
		t.Fatalf("add evidence failed: %v", err)
	}

	_, err = service.AddTimelineEvent(uuid.MustParse(incidentID), "file_encryption", "endpoint-monitor", map[string]interface{}{"user": "analyst"})
	if err != nil {
		t.Fatalf("add timeline failed: %v", err)
	}

	resp3, err := http.Get(ts.URL + "/api/v1/dfir/incidents/" + incidentID + "/evidence")
	if err != nil {
		t.Fatalf("evidence request failed: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for evidence, got %d", resp3.StatusCode)
	}

	resp4, err := http.Get(ts.URL + "/api/v1/dfir/incidents/" + incidentID + "/timeline")
	if err != nil {
		t.Fatalf("timeline request failed: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for timeline, got %d", resp4.StatusCode)
	}
}
