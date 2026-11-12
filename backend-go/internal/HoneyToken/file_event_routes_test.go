package honeytoken

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestRegisterFileEventRoutesIncludesCanaryAccessSimulation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	RegisterFileEventRoutes(
		engine.Group("/api/v1"),
		NewFileEventHandler(&FileEventService{}),
		&pgxpool.Pool{},
	)

	expectedRoutes := map[string]bool{
		http.MethodPost + " /api/v1/file-events/canary/:id/simulate-access":      false,
		http.MethodPost + " /api/v1/file-events/canary/:id/simulate/:event_type": false,
	}
	for _, route := range engine.Routes() {
		key := route.Method + " " + route.Path
		if _, exists := expectedRoutes[key]; exists {
			expectedRoutes[key] = true
		}
	}
	for route, found := range expectedRoutes {
		require.True(t, found, "simulation route was not registered: %s", route)
	}
}
