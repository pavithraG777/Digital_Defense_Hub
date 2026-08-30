package threatcorrelation

import (
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
)

func TestList(t *testing.T) {
    gin.SetMode(gin.TestMode)
    w := httptest.NewRecorder()
    c, _ := gin.CreateTestContext(w)
    req := httptest.NewRequest("GET", "/api/v1/threatcorrelation/list", nil)
    c.Request = req

    h := NewHandler()
    h.List(c)

    if w.Code != 200 {
        t.Fatalf("expected 200, got %d", w.Code)
    }
}
