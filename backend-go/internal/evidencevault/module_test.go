package evidencevault

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestListCases(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/api/v1/evidencevault/cases?status=open", nil)
	c.Request = req

	h := NewHandler()
	h.ListCases(c)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestPreserveBadPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("POST", "/api/v1/evidencevault/preserve", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h := NewHandler()
	h.Preserve(c)

	if w.Code != 400 {
		t.Fatalf("expected 400 for bad payload, got %d", w.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if success, ok := body["success"].(bool); !ok || success {
		t.Fatalf("expected success=false for bad payload, got %v", body["success"])
	}
}

func TestPreserveOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	payload := `{"case_id":"11111111-1111-1111-1111-111111111111","items":["file1","file2"],"retention_days":365}`
	req := httptest.NewRequest("POST", "/api/v1/evidencevault/preserve", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h := NewHandler()
	h.Preserve(c)

	if w.Code != 202 {
		t.Fatalf("expected 202 for accepted preserve, got %d", w.Code)
	}
}
