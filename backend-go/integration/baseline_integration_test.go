package integration

import (
    "context"
    "testing"

    bl "github.com/pavithraG777/cyber-security-platform/backend/internal/baseline"
    "github.com/google/uuid"
)

func TestIntegration_BaselineAnalyze(t *testing.T) {
    pool := getTestDatabasePool(t)
    defer pool.Close()

    repo, err := bl.NewRepository(pool)
    if err != nil {
        t.Fatalf("repo create: %v", err)
    }
    if err := repo.EnsureSchema(context.Background()); err != nil {
        t.Fatalf("ensure schema: %v", err)
    }

    svc := bl.NewService(repo)
    orgID := uuid.New()

    detected, err := svc.AnalyzeMetric(context.Background(), orgID, "cpu_usage", 95.0, map[string]interface{}{"note":"integration"})
    if err != nil {
        t.Fatalf("analyze error: %v", err)
    }
    if !detected {
        t.Fatalf("expected anomaly detected")
    }

    rows, err := repo.ListAnomalies(context.Background(), orgID, 10, 0)
    if err != nil {
        t.Fatalf("list anomalies: %v", err)
    }
    if len(rows) == 0 {
        t.Fatalf("expected persisted anomaly")
    }
}
