package integration

import (
    "context"
    "testing"

    tc "github.com/pavithraG777/cyber-security-platform/backend/internal/threatcorrelation"
    "github.com/google/uuid"
)

func TestIntegration_CorrelateEvents(t *testing.T) {
    pool := getTestDatabasePool(t)
    defer pool.Close()

    repo, err := tc.NewRepository(pool)
    if err != nil {
        t.Fatalf("repo create: %v", err)
    }
    if err := repo.EnsureSchema(context.Background()); err != nil {
        t.Fatalf("ensure schema: %v", err)
    }

    svc := tc.NewService(repo)
    orgID := uuid.New()
    events := []tc.Event{{SourceIP: "9.9.9.9", UserID: "u1"}, {SourceIP: "9.9.9.9", UserID: "u2"}}

    corr, err := svc.CorrelateEvents(context.Background(), orgID, events)
    if err != nil {
        t.Fatalf("correlate error: %v", err)
    }
    if corr == nil {
        t.Fatalf("expected correlation persisted")
    }

    // verify persisted
    rows, err := repo.ListCorrelations(context.Background(), orgID, 10, 0)
    if err != nil {
        t.Fatalf("list correlations: %v", err)
    }
    if len(rows) == 0 {
        t.Fatalf("expected at least one correlation")
    }
}
