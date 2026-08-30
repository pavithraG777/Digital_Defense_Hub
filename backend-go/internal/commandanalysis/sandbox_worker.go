package commandanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"time"
)

type SandboxWorker struct {
	db                *pgxpool.Pool
	url, token, owner string
	client            *http.Client
}

func NewSandboxWorker(db *pgxpool.Pool, url, token string) *SandboxWorker {
	return &SandboxWorker{db: db, url: url, token: token, owner: uuid.NewString(), client: &http.Client{Timeout: 2 * time.Minute}}
}
func (w *SandboxWorker) Start(ctx context.Context) error {
	if w.db == nil || w.url == "" {
		return errors.New("sandbox worker configuration is incomplete")
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
func (w *SandboxWorker) ProcessOne(ctx context.Context) (bool, error) {
	tx, e := w.db.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(ctx)
	var job, org, analysis uuid.UUID
	var artifact, hash, language string
	e = tx.QueryRow(ctx, `SELECT j.id,j.organization_id,j.analysis_id,a.artifact_uri,a.script_sha256,a.language FROM command_sandbox_jobs j JOIN command_analysis_results a ON a.id=j.analysis_id AND a.organization_id=j.organization_id WHERE (j.status='QUEUED' OR (j.status='RUNNING' AND j.started_at<NOW()-INTERVAL '5 minutes')) AND j.attempt_count<3 ORDER BY j.created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&job, &org, &analysis, &artifact, &hash, &language)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	_, e = tx.Exec(ctx, `UPDATE command_sandbox_jobs SET status='RUNNING',attempt_count=attempt_count+1,started_at=NOW(),last_error=NULL WHERE id=$1`, job)
	if e != nil {
		return false, e
	}
	if e = tx.Commit(ctx); e != nil {
		return false, e
	}
	body, _ := json.Marshal(map[string]any{"job_id": job, "organization_id": org, "artifact_uri": artifact, "expected_sha256": hash, "language": language, "isolation_profile": "NO_NETWORK_EPHEMERAL_READONLY", "limits": map[string]any{"timeout_seconds": 120, "memory_mb": 512, "cpu_seconds": 30}})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if e == nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+w.token)
		var res *http.Response
		res, e = w.client.Do(req)
		if e == nil {
			defer res.Body.Close()
			if res.StatusCode < 200 || res.StatusCode >= 300 {
				e = errors.New("sandbox runner rejected job")
			} else {
				var result map[string]any
				e = json.NewDecoder(res.Body).Decode(&result)
				if e == nil {
					result["runner_accepted"] = true
					result["artifact_sha256"] = hash
					_, e = w.db.Exec(ctx, `UPDATE command_sandbox_jobs SET status='COMPLETED',result=$2,completed_at=NOW() WHERE id=$1`, job, result)
					return true, e
				}
			}
		}
	}
	if e != nil {
		_, _ = w.db.Exec(ctx, `UPDATE command_sandbox_jobs SET status=CASE WHEN attempt_count>=3 THEN 'FAILED' ELSE 'QUEUED' END,last_error=$2 WHERE id=$1`, job, e.Error())
		return true, e
	}
	return true, errors.New("sandbox runner returned no result")
}
