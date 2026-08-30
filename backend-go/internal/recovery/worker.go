package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Worker struct {
	db     *pgxpool.Pool
	url    string
	token  string
	owner  string
	client *http.Client
}

func NewWorker(db *pgxpool.Pool, url, token string) *Worker {
	return &Worker{db: db, url: url, token: token, owner: uuid.NewString(), client: &http.Client{Timeout: 5 * time.Minute}}
}

func (w *Worker) Start(ctx context.Context) error {
	if w.db == nil || w.url == "" {
		return errors.New("recovery runner configuration is incomplete")
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = w.ProcessOne(ctx)
			}
		}
	}()
	return nil
}

func (w *Worker) ProcessOne(ctx context.Context) (bool, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var execution, org, plan uuid.UUID
	var status string
	var actions []Action
	err = tx.QueryRow(ctx, `SELECT e.id,e.organization_id,e.plan_id,e.status,p.actions FROM recovery_executions e JOIN recovery_plans p ON p.id=e.plan_id AND p.organization_id=e.organization_id LEFT JOIN recovery_controls c ON c.organization_id=e.organization_id WHERE e.status IN('QUEUED','ROLLBACK_QUEUED') AND e.attempt_count<3 AND COALESCE(c.emergency_stop,false)=false ORDER BY e.created_at FOR UPDATE OF e SKIP LOCKED LIMIT 1`).Scan(&execution, &org, &plan, &status, &actions)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	running := "RUNNING"
	if status == "ROLLBACK_QUEUED" {
		running = "ROLLING_BACK"
	}
	_, err = tx.Exec(ctx, `UPDATE recovery_executions SET status=$2,attempt_count=attempt_count+1,worker_owner=$3,started_at=COALESCE(started_at,NOW()),last_error=NULL,updated_at=NOW() WHERE id=$1`, execution, running, w.owner)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}

	payload, _ := json.Marshal(map[string]any{"execution_id": execution, "organization_id": org, "plan_id": plan, "mode": map[bool]string{true: "ROLLBACK", false: "EXECUTE"}[status == "ROLLBACK_QUEUED"], "actions": actions})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(payload))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+w.token)
		var res *http.Response
		res, err = w.client.Do(req)
		if err == nil {
			defer res.Body.Close()
			if res.StatusCode < 200 || res.StatusCode >= 300 {
				err = fmt.Errorf("recovery runner returned status %d", res.StatusCode)
			} else {
				var runnerResult map[string]any
				err = json.NewDecoder(res.Body).Decode(&runnerResult)
				if err == nil {
					runnerResult["worker_owner"] = w.owner
					final := "SUCCEEDED"
					resultColumn := "result"
					planStatus := "SUCCEEDED"
					if status == "ROLLBACK_QUEUED" {
						final, resultColumn, planStatus = "ROLLED_BACK", "rollback_result", "ROLLED_BACK"
					}
					_, err = w.db.Exec(ctx, `UPDATE recovery_executions SET status=$2,`+resultColumn+`=$3,completed_at=NOW(),updated_at=NOW() WHERE id=$1`, execution, final, runnerResult)
					if err == nil {
						_, err = w.db.Exec(ctx, `UPDATE recovery_plans SET status=$3,updated_at=NOW() WHERE id=$1 AND organization_id=$2`, plan, org, planStatus)
					}
					if err == nil {
						_, _ = w.db.Exec(ctx, `INSERT INTO recovery_audit_events(id,organization_id,plan_id,execution_id,event_type,details) VALUES($1,$2,$3,$4,$5,$6)`, uuid.New(), org, plan, execution, "EXECUTION_"+final, runnerResult)
					}
					return true, err
				}
			}
		}
	}
	if err != nil {
		_, _ = w.db.Exec(ctx, `UPDATE recovery_executions SET status=CASE WHEN attempt_count>=3 THEN 'FAILED' ELSE $2 END,last_error=$3,updated_at=NOW() WHERE id=$1`, execution, status, err.Error())
		return true, err
	}
	return true, errors.New("recovery runner returned no result")
}
