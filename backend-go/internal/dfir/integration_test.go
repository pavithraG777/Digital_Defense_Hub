package dfir

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
)

func TestDFIRIntegration_IngestToWorker(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := NewService()
	mlCfg := config.DFIRMLConfig{Timeout: 1 * time.Second}
	h := NewHandler(service, mlCfg)
	w := NewWorker(service, "", "", 100*time.Millisecond)
	h.SetWorker(w)

	// start worker
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Start(ctx)

	// setup router
	r := gin.New()
	r.POST("/api/v1/dfir/ingest", h.EnqueueEvent)

	ts := httptest.NewServer(r)
	defer ts.Close()

	// post ingest payload
	payload := map[string]string{
		"organization_id": uuid.New().String(),
		"file_event_id":   uuid.New().String(),
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", ts.URL+"/api/v1/dfir/ingest", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	resp.Body.Close()

	// wait for worker to process (polling)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if w.ProcessedCount() > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("worker did not process enqueued event; processed=%d", w.ProcessedCount())
}
