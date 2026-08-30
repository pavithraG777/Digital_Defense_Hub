package recoveryrunner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRunnerSimulatesAllowedRecoveryWithoutHostMutation(t *testing.T) {
	token := strings.Repeat("r", 32)
	service, err := New(token)
	require.NoError(t, err)
	body := `{"execution_id":"` + uuid.NewString() + `","organization_id":"` + uuid.NewString() + `","plan_id":"` + uuid.NewString() + `","mode":"EXECUTE","actions":[{"type":"ISOLATE_DEVICE","target_type":"DEVICE","target_id":"device-01"}]}`
	request := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	service.Handler().ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	var result Result
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.True(t, result.Success)
	require.Equal(t, "SAFE_LOCAL_SIMULATION", result.ExecutionMode)
	require.Equal(t, "SIMULATED", result.Actions[0].Status)
}

func TestRunnerRejectsUnknownRecoveryAction(t *testing.T) {
	token := strings.Repeat("r", 32)
	service, err := New(token)
	require.NoError(t, err)
	body := `{"execution_id":"` + uuid.NewString() + `","organization_id":"` + uuid.NewString() + `","plan_id":"` + uuid.NewString() + `","mode":"EXECUTE","actions":[{"type":"RUN_ARBITRARY_COMMAND","target_type":"DEVICE","target_id":"device-01"}]}`
	request := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	service.Handler().ServeHTTP(response, request)

	require.Equal(t, http.StatusBadRequest, response.Code)
}
