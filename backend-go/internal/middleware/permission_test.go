package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestNormalizeRequiredPermissions(t *testing.T) {
	t.Parallel()

	require.Equal(
		t,
		[]string{"HONEYTOKEN_VIEW_ACCESS_LOG", "CANARY_FILE_VIEW_EVENTS"},
		normalizeRequiredPermissions([]string{
			" honeytoken_view_access_log ",
			"CANARY_FILE_VIEW_EVENTS",
			"HONEYTOKEN_VIEW_ACCESS_LOG",
			" ",
		}),
	)
}

func TestRequireAnyPermissionRejectsUnauthenticatedRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/file-events", nil)

	RequireAnyPermission(
		nil,
		"HONEYTOKEN_VIEW_ACCESS_LOG",
		"CANARY_FILE_VIEW_EVENTS",
	)(context)

	require.True(t, context.IsAborted())
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestRequireAnyPermissionRejectsEmptyConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/file-events", nil)
	context.Set("user_id", uuid.New())

	RequireAnyPermission(nil, "", " ")(context)

	require.True(t, context.IsAborted())
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
}
