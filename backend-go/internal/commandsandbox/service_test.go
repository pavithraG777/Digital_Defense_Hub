package commandsandbox

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHandlerRejectsMissingAuthentication(t *testing.T) {
	service, err := New(t.TempDir(), strings.Repeat("a", 32), "docker", time.Second)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "/analyze", strings.NewReader(`{}`))
	response := httptest.NewRecorder()

	service.Handler().ServeHTTP(response, request)

	require.Equal(t, http.StatusUnauthorized, response.Code)
}

func TestResolveArtifactRejectsPathOutsideManagedRoot(t *testing.T) {
	service, err := New(t.TempDir(), strings.Repeat("a", 32), "docker", time.Second)
	require.NoError(t, err)

	_, err = service.resolveArtifact("../outside-script.sh")

	require.ErrorContains(t, err, "outside sandbox root")
}

func TestRuntimeForUsesPinnedIsolatedImages(t *testing.T) {
	image, command, err := runtimeFor("PYTHON")

	require.NoError(t, err)
	require.Equal(t, "python:3.12-alpine", image)
	require.Equal(t, []string{"python", "/artifact/input"}, command)
}

func TestRuntimeForRejectsHostCMDExecution(t *testing.T) {
	_, _, err := runtimeFor("CMD")

	require.Error(t, err)
}
