package credentialabuse

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestListEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/api/v1/credentialabuse/events?q=failed", nil)
	c.Request = req

	h := NewHandler()
	h.ListEvents(c)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if succeeded, ok := body["success"].(bool); !ok || !succeeded {
		t.Fatalf("unexpected success field: %v", body["success"])
	}
}

func TestRiskSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/api/v1/credentialabuse/risks", nil)
	c.Request = req

	h := NewHandler()
	h.RiskSummary(c)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
