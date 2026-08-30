package baseline

import (
    "context"
    "testing"

    "github.com/google/uuid"
)

func TestAnalyzeMetric_DetectsAnomaly(t *testing.T) {
    svc := NewService(nil)
    orgID := uuid.New()
    detected, err := svc.AnalyzeMetric(context.Background(), orgID, "cpu_usage", 95.0, map[string]interface{}{"note": "high"})
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if !detected {
        t.Fatalf("expected anomaly to be detected")
    }
}

func TestAnalyzeMetric_NoAnomaly(t *testing.T) {
    svc := NewService(nil)
    orgID := uuid.New()
    detected, err := svc.AnalyzeMetric(context.Background(), orgID, "cpu_usage", 10.0, nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if detected {
        t.Fatalf("did not expect anomaly")
    }
}
