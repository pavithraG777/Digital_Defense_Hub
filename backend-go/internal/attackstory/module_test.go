package attackstory

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTimeline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/api/v1/attackstory/timeline", nil)
	c.Request = req

	h := NewHandler()
	h.Timeline(c)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/api/v1/attackstory/summary", nil)
	c.Request = req

	h := NewHandler()
	h.Summary(c)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
