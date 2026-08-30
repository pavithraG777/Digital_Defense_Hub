package dfir

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type Worker struct {
	service     *Service
	mlEngineURL string
	token       string
	httpClient  *http.Client

	queue chan map[string]interface{}

	processed uint64
}

func NewWorker(s *Service, mlEngineURL string, token string, timeout time.Duration) *Worker {
	return &Worker{
		service:     s,
		mlEngineURL: mlEngineURL,
		token:       token,
		httpClient:  &http.Client{Timeout: timeout},
		queue:       make(chan map[string]interface{}, 256),
	}
}

func (w *Worker) Start(ctx context.Context) error {
	if w == nil {
		return nil
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-w.queue:
				// process event synchronously: infer features, rule score, call ML
				// We reuse existing helpers
				signals := inferSignalsFromEvent(ev)
				ar := AssessmentRequest{Signals: signals, EvidenceCount: intValue(ev["evidence_count"])}
				_ = w.service.AssessRansomwareIndicators(ar)

				// call ML service if configured (best-effort; ignore errors)
				if w.mlEngineURL != "" {
					features := buildFeaturePayloadFromEvent(ev)
					body, _ := json.Marshal(features)
					httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, w.mlEngineURL+"/score", bytes.NewReader(body))
					httpReq.Header.Set("Content-Type", "application/json")
					if w.token != "" {
						httpReq.Header.Set("Authorization", "Bearer "+w.token)
					}
					resp, err := w.httpClient.Do(httpReq)
					if err == nil && resp != nil {
						resp.Body.Close()
					}
				}

				atomic.AddUint64(&w.processed, 1)
			}
		}
	}()
	return nil
}

func (w *Worker) Enqueue(ev map[string]interface{}) error {
	if w == nil {
		return nil
	}
	select {
	case w.queue <- ev:
		return nil
	default:
		// queue full, drop
		return nil
	}
}

func (w *Worker) ProcessedCount() uint64 {
	return atomic.LoadUint64(&w.processed)
}

// TrySubmitFileEventAnalysis allows the HoneyToken FileEventService to
// non-blockingly submit a file event reference for DFIR analysis. It
// implements the same pattern used by other analysis workers.
func (w *Worker) TrySubmitFileEventAnalysis(
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
) bool {
	if w == nil || organizationID == uuid.Nil || fileEventID == uuid.Nil {
		return false
	}

	// If worker not started yet, treat as unavailable
	// We don't track started state here; best-effort enqueue only.
	select {
	case w.queue <- map[string]interface{}{
		"organization_id": organizationID.String(),
		"file_event_id":   fileEventID.String(),
	}:
		return true
	default:
		return false
	}
}
