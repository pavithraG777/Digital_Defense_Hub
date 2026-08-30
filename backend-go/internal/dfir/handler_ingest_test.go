package dfir

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
)

func TestEnqueueEventHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := NewService()
	h := NewHandler(service, config.DFIRMLConfig{Timeout: 1 * time.Second})
	w := NewWorker(service, "", "", 1*time.Second)
	h.SetWorker(w)

	// create test event payload
	event := map[string]interface{}{"some": "value"}
	body, _ := json.Marshal(event)

	req := httptest.NewRequest("POST", "/ingest", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	h.EnqueueEvent(c)

	if rec.Code != 200 {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
}
