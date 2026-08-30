package securityevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxAttempts = 5

type Worker struct {
	db       *pgxpool.Pool
	owner    string
	interval time.Duration
	now      func() time.Time
}
type outboxItem struct {
	ID, OrganizationID, EventID uuid.UUID
	Topic                       string
	Payload                     []byte
	Attempts                    int
}

func NewWorker(db *pgxpool.Pool) *Worker {
	return &Worker{db: db, owner: uuid.NewString(), interval: 500 * time.Millisecond, now: func() time.Time { return time.Now().UTC() }}
}
func (w *Worker) Start(ctx context.Context) error {
	if w == nil || w.db == nil {
		return errors.New("security event worker database is required")
	}
	go w.run(ctx)
	return nil
}
func (w *Worker) run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := 0; i < 20; i++ {
				processed, e := w.ProcessOne(ctx)
				if e != nil || !processed {
					break
				}
			}
		}
	}
}
func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	seconds := math.Pow(2, float64(attempt-1))
	if seconds > 300 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}
func (w *Worker) claim(ctx context.Context) (*outboxItem, error) {
	tx, e := w.db.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	item := new(outboxItem)
	e = tx.QueryRow(ctx, `SELECT id,organization_id,event_id,topic,payload,attempt_count FROM security_event_outbox WHERE (status IN('PENDING','RETRY') AND next_attempt_at<=NOW()) OR (status='PROCESSING' AND lease_until<NOW()) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&item.ID, &item.OrganizationID, &item.EventID, &item.Topic, &item.Payload, &item.Attempts)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	tag, e := tx.Exec(ctx, `UPDATE security_event_outbox SET status='PROCESSING',lease_owner=$2,lease_until=NOW()+INTERVAL '30 seconds',attempt_count=attempt_count+1 WHERE id=$1`, item.ID, w.owner)
	if e != nil || tag.RowsAffected() != 1 {
		return nil, fmt.Errorf("claim outbox item: %w", e)
	}
	item.Attempts++
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return item, nil
}
func (w *Worker) ProcessOne(ctx context.Context) (bool, error) {
	item, e := w.claim(ctx)
	if e != nil || item == nil {
		return false, e
	}
	if e = w.process(ctx, item); e != nil {
		_ = w.fail(ctx, item, e)
		return true, e
	}
	return true, w.complete(ctx, item)
}
func (w *Worker) process(ctx context.Context, item *outboxItem) error {
	if item.Topic != "security.event.normalized" && item.Topic != "security.event.replay" {
		return fmt.Errorf("poison event: unsupported topic %q", item.Topic)
	}
	if !json.Valid(item.Payload) {
		return errors.New("poison event: invalid outbox payload")
	}
	rows, e := w.db.Query(ctx, `SELECT entity_id FROM security_event_entities WHERE organization_id=$1 AND event_id=$2 ORDER BY entity_id`, item.OrganizationID, item.EventID)
	if e != nil {
		return e
	}
	defer rows.Close()
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if e = rows.Scan(&id); e != nil {
			return e
		}
		ids = append(ids, id)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	tx, e := w.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			_, e = tx.Exec(ctx, `INSERT INTO security_entity_edges(id,organization_id,source_entity_id,target_entity_id,relationship_type,first_seen_at,last_seen_at,event_count,confidence) SELECT $1,$2,$3,$4,'CO_OCCURRENCE',observed_at,observed_at,1,1 FROM normalized_security_events WHERE organization_id=$2 AND id=$5 ON CONFLICT(organization_id,source_entity_id,target_entity_id,relationship_type) DO UPDATE SET last_seen_at=GREATEST(security_entity_edges.last_seen_at,EXCLUDED.last_seen_at),event_count=security_entity_edges.event_count+1`, uuid.New(), item.OrganizationID, ids[i], ids[j], item.EventID)
			if e != nil {
				return e
			}
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	if e = correlateEvent(ctx, w.db, item.OrganizationID, item.EventID); e != nil {
		return e
	}
	return processIntelligence(ctx, w.db, item.OrganizationID, item.EventID)
}
func (w *Worker) complete(ctx context.Context, item *outboxItem) error {
	tx, e := w.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `UPDATE security_event_outbox SET status='PUBLISHED',published_at=NOW(),lease_owner=NULL,lease_until=NULL,last_error=NULL WHERE id=$1 AND lease_owner=$2`, item.ID, w.owner)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE normalized_security_events SET processing_status='PROCESSED',last_error=NULL WHERE organization_id=$1 AND id=$2`, item.OrganizationID, item.EventID)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (w *Worker) fail(ctx context.Context, item *outboxItem, cause error) error {
	tx, e := w.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if item.Attempts >= maxAttempts {
		_, e = tx.Exec(ctx, `INSERT INTO security_event_dead_letters(id,organization_id,event_id,outbox_id,reason,payload,attempt_count) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), item.OrganizationID, item.EventID, item.ID, cause.Error(), item.Payload, item.Attempts)
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE security_event_outbox SET status='DEAD_LETTER',last_error=$2,lease_owner=NULL,lease_until=NULL WHERE id=$1`, item.ID, cause.Error())
		}
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE normalized_security_events SET processing_status='DEAD_LETTER',last_error=$3 WHERE organization_id=$1 AND id=$2`, item.OrganizationID, item.EventID, cause.Error())
		}
	} else {
		_, e = tx.Exec(ctx, `UPDATE security_event_outbox SET status='RETRY',next_attempt_at=$2,last_error=$3,lease_owner=NULL,lease_until=NULL WHERE id=$1`, item.ID, w.now().Add(retryDelay(item.Attempts)), cause.Error())
	}
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
