package deepfakeforensics

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func TestNewAnalysisWorkerAllowsMissingEngineClient(t *testing.T) {
	repo := &Repository{databasePool: &pgxpool.Pool{}}
	worker, err := NewAnalysisWorker(repo, nil, zap.NewNop(), 1, 0, 0, "")
	if err != nil {
		t.Fatalf("expected worker creation to succeed without engine client, got %v", err)
	}
	if worker == nil {
		t.Fatal("expected non-nil worker")
	}
}
