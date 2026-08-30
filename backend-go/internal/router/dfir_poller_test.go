package router

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeRows struct {
	entries [][]any
	idx     int
}

func (r *fakeRows) Next() bool {
	if r.idx >= len(r.entries) {
		return false
	}
	r.idx++
	return true
}

func (r *fakeRows) Scan(dest ...any) error {
	if r.idx == 0 || r.idx > len(r.entries) {
		return errors.New("no row available")
	}
	row := r.entries[r.idx-1]
	if len(dest) != len(row) {
		return errors.New("scan destination mismatch")
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *uuid.UUID:
			if val, ok := row[i].(uuid.UUID); ok {
				*d = val
			} else {
				return errors.New("invalid uuid type")
			}
		default:
			return errors.New("unsupported scan destination type")
		}
	}
	return nil
}

func (r *fakeRows) Close() {}

func (r *fakeRows) Err() error { return nil }

func (r *fakeRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }

func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

func (r *fakeRows) Values() ([]any, error) { return nil, nil }

func (r *fakeRows) RawValues() [][]byte { return nil }

func (r *fakeRows) Conn() *pgx.Conn { return nil }

type fakeQueryer struct {
	rows pgx.Rows
}

func (q *fakeQueryer) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return q.rows, nil
}

type fakeThreatRepository struct {
	expectedOrgID   uuid.UUID
	expectedEventID uuid.UUID
	claimed         bool
}

func (f *fakeThreatRepository) ClaimFileEventForThreatAnalysis(
	ctx context.Context,
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
) (bool, error) {
	if organizationID == f.expectedOrgID && fileEventID == f.expectedEventID {
		f.claimed = true
		return true, nil
	}
	return false, nil
}

type fakeWorker struct {
	received []map[string]interface{}
}

func (w *fakeWorker) TrySubmitFileEventAnalysis(organizationID uuid.UUID, fileEventID uuid.UUID) bool {
	w.received = append(w.received, map[string]interface{}{
		"organization_id": organizationID.String(),
		"file_event_id":   fileEventID.String(),
	})
	return true
}

func TestStartDFIRPoller_ClaimsEventsAndEnqueues(t *testing.T) {
	orgID := uuid.New()
	fileEventID := uuid.New()

	fakeRows := &fakeRows{entries: [][]any{{fileEventID, orgID}}}
	queryer := &fakeQueryer{rows: fakeRows}
	threatRepo := &fakeThreatRepository{expectedOrgID: orgID, expectedEventID: fileEventID}
	worker := &fakeWorker{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartDFIRPoller(ctx, queryer, threatRepo, worker, 10*time.Millisecond)

	time.Sleep(50 * time.Millisecond)

	if !threatRepo.claimed {
		t.Fatal("expected threat repository to claim the file event")
	}
	if len(worker.received) != 1 {
		t.Fatalf("expected one enqueued event, got %d", len(worker.received))
	}
	if worker.received[0]["organization_id"] != orgID.String() || worker.received[0]["file_event_id"] != fileEventID.String() {
		t.Fatalf("unexpected event payload: %#v", worker.received[0])
	}
}
