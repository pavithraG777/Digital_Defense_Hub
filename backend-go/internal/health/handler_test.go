package health

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMetricsRequiresConfiguredToken(t *testing.T) {
	t.Setenv("METRICS_BEARER_TOKEN", "secret")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", Metrics(nil))
	unauthorized := httptest.NewRecorder()
	r.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret")
	r.ServeHTTP(authorized, req)
	if authorized.Code != http.StatusOK || !strings.Contains(authorized.Body.String(), "ddh_api_up 1") {
		t.Fatalf("unexpected metrics response: %d %s", authorized.Code, authorized.Body.String())
	}
}
