package honeytoken

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestRegisterCanaryRoutesIncludesSeparatedCRUDEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	RegisterCanaryRoutes(
		engine.Group("/api/v1"),
		NewCanaryHandler(&CanaryService{}),
		&pgxpool.Pool{},
	)

	expectedRoutes := map[string]bool{
		http.MethodPost + " /api/v1/canary-files":            false,
		http.MethodPost + " /api/v1/canary-files/import":     false,
		http.MethodGet + " /api/v1/canary-files":             false,
		http.MethodGet + " /api/v1/canary-files/:id":         false,
		http.MethodPost + " /api/v1/canary-files/:id/deploy": false,
	}

	for _, route := range engine.Routes() {
		key := route.Method + " " + route.Path
		if _, exists := expectedRoutes[key]; exists {
			expectedRoutes[key] = true
		}
	}

	for route, found := range expectedRoutes {
		require.True(t, found, "canary route was not registered: %s", route)
	}
}
