package auditlog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type recordingAuditRepository struct {
	entries []*AuditLog
}

func (r *recordingAuditRepository) Create(
	_ context.Context,
	entry *AuditLog,
) error {
	copyOfEntry := *entry
	r.entries = append(r.entries, &copyOfEntry)
	return nil
}

func (r *recordingAuditRepository) List(
	_ context.Context,
) ([]AuditLog, error) {
	return nil, nil
}

func (r *recordingAuditRepository) GetByID(
	_ context.Context,
	_ string,
) (*AuditLog, error) {
	return nil, nil
}

func TestMiddlewareAuditsPublicMutationAndRedactsQuerySecrets(
	t *testing.T,
) {
	gin.SetMode(gin.TestMode)
	repository := &recordingAuditRepository{}
	engine := gin.New()
	engine.Use(Middleware(NewService(repository)))

	organizationID := uuid.New()
	userID := uuid.New()
	engine.POST("/api/v1/auth/login", func(c *gin.Context) {
		c.Set("organization_id", organizationID)
		c.Set("user_id", userID)
		c.Status(http.StatusOK)
	})

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/login?email=analyst%40example.com&token=secret-value&mfa_code=123456",
		nil,
	)
	request.Header.Set("User-Agent", "PostmanRuntime/7.0")
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Len(t, repository.entries, 1)
	entry := repository.entries[0]
	require.Equal(t, "AUTH", entry.ModuleName)
	require.Equal(t, "CREATE", entry.ActionName)
	require.Equal(t, ResultStatusSuccess, entry.ResultStatus)
	require.Equal(t, &organizationID, entry.OrganizationID)
	require.Equal(t, &userID, entry.UserID)
	require.Equal(
		t,
		"email=analyst%40example.com&mfa_code=%5BREDACTED%5D&token=%5BREDACTED%5D",
		entry.Metadata["query_string"],
	)
}

func TestMiddlewareSkipsOperationalProbeEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repository := &recordingAuditRepository{}
	engine := gin.New()
	engine.Use(Middleware(NewService(repository)))
	engine.GET("/api/v1/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/health",
		nil,
	)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Empty(t, repository.entries)
}

func TestPrepareAuditLogRedactsNestedAuthenticationMaterial(
	t *testing.T,
) {
	entry := &AuditLog{
		ModuleName: "auth",
		ActionName: "update",
		NewValues: map[string]any{
			"profile": map[string]any{
				"mfa_code":      "123456",
				"client_secret": "do-not-store",
				"display_name":  "Analyst",
			},
		},
	}

	prepareAuditLog(entry)

	profile := entry.NewValues["profile"].(map[string]any)
	require.Equal(t, "[REDACTED]", profile["mfa_code"])
	require.Equal(t, "[REDACTED]", profile["client_secret"])
	require.Equal(t, "Analyst", profile["display_name"])
}
