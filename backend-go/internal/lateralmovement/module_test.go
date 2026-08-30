package lateralmovement

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestListAlerts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/api/v1/lateralmovement/alerts?page=2", nil)
	c.Request = req

	h := NewHandler()
	h.ListAlerts(c)

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

	if page, ok := body["page"].(string); !ok || page != "2" {
		t.Fatalf("unexpected page value: %v", body["page"])
	}
}

func TestDeviceGraph(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/api/v1/lateralmovement/graph", nil)
	c.Request = req

	h := NewHandler()
	h.DeviceGraph(c)

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
