package router

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type claimable interface {
	ClaimFileEventForThreatAnalysis(context.Context, uuid.UUID, uuid.UUID) (bool, error)
}

type dfirWorker interface {
	TrySubmitFileEventAnalysis(uuid.UUID, uuid.UUID) bool
}

// StartDFIRPoller starts a lightweight poller that scans the file_events
// table for received/queued events, attempts to claim them atomically using
// the ThreatRepository, and enqueues claimed events to the DFIR worker.
func StartDFIRPoller(
	ctx context.Context,
	db queryer,
	threatRepo claimable,
	worker dfirWorker,
	interval time.Duration,
) {
	if db == nil || threatRepo == nil || worker == nil {
		return
	}

	if interval <= 0 {
		interval = 5 * time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Query a small batch of candidate file events
				rows, err := db.Query(context.Background(), `
                    SELECT id, organization_id
                    FROM file_events
                    WHERE status IN ('RECEIVED','QUEUED')
                    ORDER BY occurred_at ASC
                    LIMIT 100
                `)
				if err != nil {
					continue
				}

				for rows.Next() {
					var id uuid.UUID
					var org uuid.UUID
					if err := rows.Scan(&id, &org); err != nil {
						continue
					}

					claimed, err := threatRepo.ClaimFileEventForThreatAnalysis(context.Background(), org, id)
					if err != nil || !claimed {
						continue
					}

					// Enqueue into DFIR worker (best-effort)
					worker.TrySubmitFileEventAnalysis(org, id)
				}
				rows.Close()
			}
		}
	}()
}
