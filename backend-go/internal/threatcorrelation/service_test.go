package threatcorrelation

import (
    "context"
    "testing"

    "github.com/google/uuid"
)

func TestCorrelateEvents_CommonSourceIP(t *testing.T) {
    svc := NewService(nil)
    orgID := uuid.New()
    events := []Event{
        {SourceIP: "1.2.3.4", UserID: "u1", Type: "login"},
        {SourceIP: "1.2.3.4", UserID: "u2", Type: "access"},
    }

    corr, err := svc.CorrelateEvents(context.Background(), orgID, events)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if corr == nil {
        t.Fatalf("expected a correlation, got nil")
    }
    if corr.CorrelationType != "common_source_ip" {
        t.Fatalf("unexpected correlation type: %s", corr.CorrelationType)
    }
}

func TestCorrelateEvents_NoCorrelation(t *testing.T) {
    svc := NewService(nil)
    orgID := uuid.New()
    events := []Event{
        {SourceIP: "1.1.1.1", UserID: "u1", Type: "login"},
        {SourceIP: "2.2.2.2", UserID: "u2", Type: "access"},
    }

    corr, err := svc.CorrelateEvents(context.Background(), orgID, events)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if corr != nil {
        t.Fatalf("expected no correlation, got one: %v", corr)
    }
}
