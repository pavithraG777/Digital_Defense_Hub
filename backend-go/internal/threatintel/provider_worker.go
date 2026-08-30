package threatintel

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

type ProviderWorker struct {
	db       *pgxpool.Pool
	owner    string
	provider intelligenceProvider
}
type intelligenceProvider interface {
	Enrich(context.Context, providerQuery) (providerResult, error)
}
type providerQuery struct {
	JobID, OrganizationID uuid.UUID
	Type, Value           string
}
type providerResult struct {
	Provider        string         `json:"provider"`
	SourceReference string         `json:"source_reference"`
	Reputation      int            `json:"reputation"`
	Confidence      int            `json:"confidence"`
	Tags            []string       `json:"tags"`
	FirstSeenAt     *time.Time     `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Raw             map[string]any `json:"raw"`
}

func NewProviderWorker(db *pgxpool.Pool, url, token string) *ProviderWorker {
	return &ProviderWorker{db: db, owner: uuid.NewString(), provider: &httpIntelligenceProvider{url: url, token: token, client: &http.Client{Timeout: 30 * time.Second}}}
}
func (w *ProviderWorker) Start(ctx context.Context) error {
	if w.db == nil || w.provider == nil {
		return errors.New("threat intelligence provider configuration is incomplete")
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
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
func (w *ProviderWorker) ProcessOne(ctx context.Context) (bool, error) {
	tx, e := w.db.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(ctx)
	var job, org uuid.UUID
	var kind, value, normalized string
	e = tx.QueryRow(ctx, `SELECT id,organization_id,indicator_type,indicator_value,normalized_value FROM threat_intelligence_jobs WHERE (status='QUEUED' OR(status='RUNNING' AND started_at<NOW()-INTERVAL '2 minutes')) AND attempt_count<3 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&job, &org, &kind, &value, &normalized)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	_, e = tx.Exec(ctx, `UPDATE threat_intelligence_jobs SET status='RUNNING',attempt_count=attempt_count+1,worker_owner=$2,started_at=NOW(),last_error=NULL WHERE id=$1`, job, w.owner)
	if e != nil {
		return false, e
	}
	if e = tx.Commit(ctx); e != nil {
		return false, e
	}
	result, e := w.provider.Enrich(ctx, providerQuery{JobID: job, OrganizationID: org, Type: kind, Value: normalized})
	if e == nil && (result.Provider == "" || result.SourceReference == "" || result.Confidence < 0 || result.Confidence > 100 || result.Reputation < 0 || result.Reputation > 100 || result.ExpiresAt.IsZero()) {
		e = errors.New("provider response lacks provenance, bounded scores, or expiry")
	}
	if e != nil {
		_, _ = w.db.Exec(ctx, `UPDATE threat_intelligence_jobs SET status=CASE WHEN attempt_count>=3 THEN 'FAILED' ELSE 'QUEUED' END,last_error=$2 WHERE id=$1`, job, e.Error())
		return true, e
	}
	if result.LastSeenAt.IsZero() {
		result.LastSeenAt = time.Now().UTC()
	}
	severity := "LOW"
	if result.Reputation >= 80 {
		severity = "CRITICAL"
	} else if result.Reputation >= 60 {
		severity = "HIGH"
	} else if result.Reputation >= 30 {
		severity = "MEDIUM"
	}
	tx, e = w.db.Begin(ctx)
	if e != nil {
		return true, e
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `INSERT INTO threat_intelligence_indicators(id,organization_id,indicator_type,indicator_value,normalized_value,reputation_score,confidence,severity,tags,sources,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE($11,$12),$12) ON CONFLICT(organization_id,indicator_type,normalized_value) DO UPDATE SET reputation_score=EXCLUDED.reputation_score,confidence=EXCLUDED.confidence,severity=EXCLUDED.severity,tags=EXCLUDED.tags,sources=EXCLUDED.sources,last_seen_at=EXCLUDED.last_seen_at,updated_at=NOW()`, uuid.New(), org, kind, value, normalized, result.Reputation, result.Confidence, severity, result.Tags, []source{{Name: result.Provider, Reputation: result.Reputation, Confidence: result.Confidence, Tags: result.Tags}}, result.FirstSeenAt, result.LastSeenAt)
	if e == nil {
		_, e = tx.Exec(ctx, `INSERT INTO threat_intelligence_provider_observations(id,organization_id,job_id,provider,source_reference,indicator_type,normalized_value,reputation,confidence,first_seen_at,last_seen_at,expires_at,raw)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, uuid.New(), org, job, result.Provider, result.SourceReference, kind, normalized, result.Reputation, result.Confidence, result.FirstSeenAt, result.LastSeenAt, result.ExpiresAt, result.Raw)
	}
	if e == nil {
		_, e = tx.Exec(ctx, `UPDATE threat_intelligence_jobs SET status='COMPLETED',completed_at=NOW(),result=$2 WHERE id=$1`, job, result)
	}
	if e != nil {
		return true, e
	}
	return true, tx.Commit(ctx)
}

type httpIntelligenceProvider struct {
	url, token string
	client     *http.Client
}

func (p *httpIntelligenceProvider) Enrich(ctx context.Context, query providerQuery) (providerResult, error) {
	if p == nil || p.client == nil || p.url == "" {
		return providerResult{}, errors.New("threat intelligence provider URL is required")
	}
	payload, err := json.Marshal(map[string]any{"job_id": query.JobID, "organization_id": query.OrganizationID, "type": query.Type, "value": query.Value})
	if err != nil {
		return providerResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(payload))
	if err != nil {
		return providerResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	res, err := p.client.Do(req)
	if err != nil {
		return providerResult{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return providerResult{}, fmt.Errorf("provider returned status %d", res.StatusCode)
	}
	var result providerResult
	err = json.NewDecoder(res.Body).Decode(&result)
	return result, err
}
