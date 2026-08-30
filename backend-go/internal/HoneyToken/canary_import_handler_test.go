package honeytoken

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestImportCanaryFileRequiresMultipartFile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/canary-files/import",
		bytes.NewReader(nil),
	)
	request.Header.Set("Content-Type", "multipart/form-data; boundary=missing")

	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request
	ctx.Set("organization_id", uuid.New())
	ctx.Set("user_id", uuid.New())

	handler := NewCanaryHandler(&CanaryService{})
	handler.ImportCanaryFile(ctx)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestImportCanaryFileRejectsFileOverTenMiB(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "large.txt")
	require.NoError(t, err)
	_, err = part.Write(make([]byte, MaxCanaryImportSize+1))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/canary-files/import",
		&body,
	)
	request.Header.Set("Content-Type", writer.FormDataContentType())

	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request
	ctx.Set("organization_id", uuid.New())
	ctx.Set("user_id", uuid.New())

	handler := NewCanaryHandler(&CanaryService{})
	handler.ImportCanaryFile(ctx)

	require.Equal(t, http.StatusRequestEntityTooLarge, recorder.Code)

	var responseBody map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &responseBody))
	require.Equal(t, false, responseBody["success"])
}

func TestCreateCanaryFileResponseDoesNotExposePhysicalPath(t *testing.T) {
	encoded, err := json.Marshal(CreateCanaryFileResponse{
		ID:         uuid.New(),
		CanaryCode: "CNY-EXAMPLE",
		FileName:   "record.txt",
		Status:     CanaryStatusDraft,
	})
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "file_path")
	require.NotContains(t, string(encoded), "storage_path")
	require.NotContains(t, string(encoded), "tracking_identifier")
}
