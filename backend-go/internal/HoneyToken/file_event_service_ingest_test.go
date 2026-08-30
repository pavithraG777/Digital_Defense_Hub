package honeytoken

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
)

func TestSubmitFileEventForDFIRAnalysis_UsesIngestURLEnv(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/dfir/ingest" {
			t.Fatalf("expected request path /api/v1/dfir/ingest, got %s", r.URL.Path)
		}
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	oldURL := os.Getenv("DFIR_INGEST_URL")
	os.Setenv("DFIR_INGEST_URL", server.URL+"/api/v1/dfir/ingest")
	defer os.Setenv("DFIR_INGEST_URL", oldURL)

	svc := &FileEventService{}
	event := &FileEvent{
		OrganizationID: uuid.New(),
		ID:             uuid.New(),
	}

	svc.submitFileEventForDFIRAnalysis(event)

	if len(receivedBody) == 0 {
		t.Fatal("expected request body, got empty")
	}

	var payload map[string]string
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal request body: %v", err)
	}

	if payload["organization_id"] != event.OrganizationID.String() {
		t.Fatalf("expected organization_id %s, got %s", event.OrganizationID.String(), payload["organization_id"])
	}
	if payload["file_event_id"] != event.ID.String() {
		t.Fatalf("expected file_event_id %s, got %s", event.ID.String(), payload["file_event_id"])
	}
}
