package operational

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestConnectorWorkerAuthorizedPathRejectsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	worker := &ConnectorWorker{allowedRoots: []string{root}}
	inside := filepath.Join(root, "sample.bin")
	require.NoError(t, os.WriteFile(inside, []byte("sample"), 0o600))
	resolved, err := worker.authorizedPath(inside)
	require.NoError(t, err)
	require.Equal(t, filepath.Clean(inside), resolved)
	_, err = worker.authorizedPath(filepath.Join(filepath.Dir(root), "outside.bin"))
	require.Error(t, err)
}

func TestMediaContractMapsOperationalModules(t *testing.T) {
	tests := []struct{ module, mime, jobType, mediaType string }{
		{"IMAGE", "image/png", "IMAGE_FORENSICS", "IMAGE"},
		{"FACE", "image/jpeg", "DEEPFAKE_IMAGE_DETECTION", "IMAGE"},
		{"AUDIO", "audio/wav", "AUDIO_FORENSICS", "AUDIO"},
		{"DOCUMENT", "application/pdf", "OCR_EXTRACTION", "DOCUMENT"},
		{"SURVEILLANCE", "video/mp4", "VIDEO_FORENSICS", "VIDEO"},
	}
	for _, test := range tests {
		jobType, mediaType, err := mediaContract(connectorJob{Module: test.module, MIMEType: test.mime})
		require.NoError(t, err)
		require.Equal(t, test.jobType, jobType)
		require.Equal(t, test.mediaType, mediaType)
	}
}

func TestEmailConnectorParsesEvidenceWithoutInventingVerdict(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "message.eml")
	body := "From: sender@example.com\r\nTo: analyst@example.com\r\nSubject: Review\r\nMessage-ID: <1@example.com>\r\nAuthentication-Results: mx.example; spf=pass\r\n\r\nSee https://example.com/report"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	worker := &ConnectorWorker{allowedRoots: []string{root}}
	result, code, err := worker.executeEmail(connectorJob{ID: uuid.New(), TargetURI: path})
	require.NoError(t, err)
	require.Empty(t, code)
	require.Equal(t, "NO_IMMEDIATE_SIGNAL", result["verdict"])
	require.Equal(t, 1, result["url_count"])
	require.NotEmpty(t, result["verified_source_sha256"])
}
