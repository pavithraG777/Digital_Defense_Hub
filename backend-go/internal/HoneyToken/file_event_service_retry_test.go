package honeytoken

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSubmitFileEventForDFIRAnalysis_Retry(t *testing.T) {
	// test server that fails first two requests, succeeds third
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	old := os.Getenv("DFIR_INGEST_URL")
	os.Setenv("DFIR_INGEST_URL", srv.URL)
	defer os.Setenv("DFIR_INGEST_URL", old)

	s := &FileEventService{}
	e := &FileEvent{
		OrganizationID: uuid.New(),
		ID:             uuid.New(),
	}

	start := time.Now()
	s.submitFileEventForDFIRAnalysis(e)
	dur := time.Since(start)

	// ensure we retried at least twice (backoff delay > 0)
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}

	// ensure some backoff time occurred (>= total backoff of 200+400 ms)
	if dur < 500*time.Millisecond {
		t.Fatalf("expected backoff delays, duration too short: %v", dur)
	}
}
