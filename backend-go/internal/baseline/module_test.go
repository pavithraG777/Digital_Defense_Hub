package baseline

import (
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
)

func TestStatus(t *testing.T) {
    gin.SetMode(gin.TestMode)
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)
    req := httptest.NewRequest("GET", "/api/v1/baseline/status", nil)
    c.Request = req

    h := NewHandler()
    h.Status(c)

    if w.Code != 200 {
        t.Fatalf("expected 200, got %d", w.Code)
    }
}

func TestAnomalies(t *testing.T) {
    gin.SetMode(gin.TestMode)
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)
    req := httptest.NewRequest("GET", "/api/v1/baseline/anomalies", nil)
    c.Request = req

    h := NewHandler()
    h.Anomalies(c)

    if w.Code != 200 {
        t.Fatalf("expected 200, got %d", w.Code)
    }
}
