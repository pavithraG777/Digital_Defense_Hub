package privilegeescalation

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestServiceAnalyzeEvent_Sudo(t *testing.T) {
	svc := NewService(nil)
	evt := map[string]any{"command": "sudo su -"}
	dt, score := svc.AnalyzeEvent(context.Background(), evt)
	if dt != "SUSPICIOUS_COMMAND" || score < 0.9 {
		t.Fatalf("unexpected detection %s score %f", dt, score)
	}
}

func TestServiceAnalyzeEvent_RoleAssign(t *testing.T) {
	svc := NewService(nil)
	evt := map[string]any{"event": "role_assignment", "role": "Admin"}
	dt, score := svc.AnalyzeEvent(context.Background(), evt)
	if dt != "PRIV_ESC_ROLE_ASSIGNMENT" || score < 0.95 {
		t.Fatalf("unexpected detection %s score %f", dt, score)
	}
}

func TestVerifyHandler_BadPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("POST", "/api/v1/privilegeescalation/verify", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h := NewHandler()
	h.Verify(c)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if success, _ := body["success"].(bool); success {
		t.Fatalf("expected success=false for bad payload")
	}
}
