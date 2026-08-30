package evidencevault

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type PreservationJob struct {
	ID                     uuid.UUID  `json:"id"`
	OrganizationID         uuid.UUID  `json:"organization_id"`
	CaseID                 uuid.UUID  `json:"case_id"`
	Items                  []string   `json:"items"`
	Status                 string     `json:"status"`
	RetentionUntil         *time.Time `json:"retention_until,omitempty"`
	LegalHold              bool       `json:"legal_hold"`
	IntegrityVerified      bool       `json:"integrity_verified"`
	CreatedBy              uuid.UUID  `json:"created_by"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	ManifestSHA256         string     `json:"manifest_sha256,omitempty"`
	PreviousManifestSHA256 string     `json:"previous_manifest_sha256,omitempty"`
	Signature              string     `json:"signature,omitempty"`
	SigningKeyID           string     `json:"signing_key_id,omitempty"`
	ObjectVersionID        string     `json:"object_version_id,omitempty"`
	EncryptionKeyID        string     `json:"encryption_key_id,omitempty"`
	ManifestEvidenceID     *uuid.UUID `json:"manifest_evidence_id,omitempty"`
}
type CustodyEvent struct {
	ID                uuid.UUID  `json:"id"`
	JobID             uuid.UUID  `json:"job_id"`
	Action            string     `json:"action"`
	FromCustodian     *uuid.UUID `json:"from_custodian,omitempty"`
	ToCustodian       *uuid.UUID `json:"to_custodian,omitempty"`
	Note              string     `json:"note"`
	ActorID           uuid.UUID  `json:"actor_id"`
	CreatedAt         time.Time  `json:"created_at"`
	PreviousEventHash string     `json:"previous_event_hash,omitempty"`
	EventHash         string     `json:"event_hash"`
}
type Repository struct{ db *pgxpool.Pool }

func NewRepository(db *pgxpool.Pool) (*Repository, error) {
	if db == nil {
		return nil, fmt.Errorf("database pool required")
	}
	return &Repository{db: db}, nil
}
func (r *Repository) EnsureSchema(ctx context.Context) error {
	queries := []string{`CREATE TABLE IF NOT EXISTS evidence_preservation_jobs(id UUID PRIMARY KEY,case_id UUID NOT NULL,items JSONB NOT NULL DEFAULT '[]',status TEXT NOT NULL DEFAULT 'PENDING',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`, `ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS organization_id UUID`, `ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS retention_until TIMESTAMPTZ`, `ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT FALSE`, `ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS integrity_verified BOOLEAN NOT NULL DEFAULT FALSE`, `ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS created_by UUID`, `ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `ALTER TABLE evidence_preservation_jobs ADD COLUMN IF NOT EXISTS manifest_evidence_id UUID`, `CREATE TABLE IF NOT EXISTS evidence_custody_events(id UUID PRIMARY KEY,organization_id UUID NOT NULL,job_id UUID NOT NULL,action TEXT NOT NULL,from_custodian UUID,to_custodian UUID,note TEXT NOT NULL,actor_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`, `ALTER TABLE evidence_custody_events ADD COLUMN IF NOT EXISTS previous_event_hash CHAR(64)`, `ALTER TABLE evidence_custody_events ADD COLUMN IF NOT EXISTS event_hash CHAR(64)`, `CREATE TABLE IF NOT EXISTS evidence_worm_attestations(id UUID PRIMARY KEY,organization_id UUID NOT NULL,evidence_id UUID NOT NULL,provider TEXT NOT NULL,bucket TEXT NOT NULL,object_version_id TEXT NOT NULL,retention_mode TEXT NOT NULL,retain_until TIMESTAMPTZ NOT NULL,legal_hold BOOLEAN NOT NULL,provider_request_id TEXT NOT NULL,attested_by UUID,attested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,evidence_id))`, `CREATE TABLE IF NOT EXISTS evidence_destruction_certificates(id UUID PRIMARY KEY,organization_id UUID NOT NULL,evidence_id UUID NOT NULL,certificate_sha256 CHAR(64) NOT NULL,certificate JSONB NOT NULL,signing_key_id TEXT NOT NULL,signature TEXT NOT NULL,approved_by UUID NOT NULL,destroyed_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(organization_id,evidence_id))`}
	for _, q := range queries {
		if _, e := r.db.Exec(ctx, q); e != nil {
			return fmt.Errorf("ensure evidence vault schema: %w", e)
		}
	}
	return nil
}
func (r *Repository) Create(ctx context.Context, job *PreservationJob) error {
	items, _ := json.Marshal(job.Items)
	_, e := r.db.Exec(ctx, `INSERT INTO evidence_preservation_jobs(id,organization_id,case_id,items,status,retention_until,legal_hold,integrity_verified,created_by,created_at,updated_at,manifest_evidence_id)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11)`, job.ID, job.OrganizationID, job.CaseID, items, job.Status, job.RetentionUntil, job.LegalHold, job.IntegrityVerified, job.CreatedBy, job.CreatedAt, job.ManifestEvidenceID)
	return e
}

// Compatibility helper retained for older callers.
func (r *Repository) CreatePreservationJob(ctx context.Context, caseID uuid.UUID, items []string) (*PreservationJob, error) {
	job := &PreservationJob{ID: uuid.New(), CaseID: caseID, Items: items, Status: "PENDING", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	return job, r.Create(ctx, job)
}
func scanJob(row interface{ Scan(...any) error }) (*PreservationJob, error) {
	j := new(PreservationJob)
	var raw []byte
	e := row.Scan(&j.ID, &j.OrganizationID, &j.CaseID, &raw, &j.Status, &j.RetentionUntil, &j.LegalHold, &j.IntegrityVerified, &j.CreatedBy, &j.CreatedAt, &j.UpdatedAt, &j.ManifestEvidenceID)
	if e != nil {
		return nil, e
	}
	_ = json.Unmarshal(raw, &j.Items)
	return j, nil
}

const selectJob = `SELECT id,organization_id,case_id,items,status,retention_until,legal_hold,integrity_verified,created_by,created_at,updated_at,manifest_evidence_id FROM evidence_preservation_jobs`

func (r *Repository) List(ctx context.Context, org uuid.UUID, status string) ([]PreservationJob, error) {
	q := selectJob + ` WHERE organization_id=$1`
	args := []any{org}
	if status != "" {
		q += ` AND status=$2`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC LIMIT 100`
	rows, e := r.db.Query(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PreservationJob{}
	for rows.Next() {
		j, e := scanJob(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}
func (r *Repository) Get(ctx context.Context, org, id uuid.UUID) (*PreservationJob, error) {
	return scanJob(r.db.QueryRow(ctx, selectJob+` WHERE organization_id=$1 AND id=$2`, org, id))
}
func (r *Repository) Transition(ctx context.Context, org, id, actor uuid.UUID, status, note string, to *uuid.UUID) (*PreservationJob, error) {
	tx, e := r.db.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `UPDATE evidence_preservation_jobs SET status=$3,legal_hold=CASE WHEN $3='LEGAL_HOLD' THEN true WHEN $3='RELEASED' THEN false ELSE legal_hold END,integrity_verified=CASE WHEN $3='VERIFIED' THEN true ELSE integrity_verified END,updated_at=NOW() WHERE organization_id=$1 AND id=$2`, org, id, status)
	if e != nil || tag.RowsAffected() != 1 {
		return nil, fmt.Errorf("evidence job not found")
	}
	var previous *string
	_ = tx.QueryRow(ctx, `SELECT event_hash FROM evidence_custody_events WHERE organization_id=$1 AND job_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, org, id).Scan(&previous)
	eventID := uuid.New()
	created := time.Now().UTC()
	previousValue := ""
	if previous != nil {
		previousValue = *previous
	}
	event := CustodyEvent{ID: eventID, JobID: id, Action: status, ToCustodian: to, Note: note, ActorID: actor, CreatedAt: created, PreviousEventHash: previousValue}
	sum := custodyHash(event, org)
	_, e = tx.Exec(ctx, `INSERT INTO evidence_custody_events(id,organization_id,job_id,action,to_custodian,note,actor_id,created_at,previous_event_hash,event_hash)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, eventID, org, id, status, to, note, actor, created, previous, sum)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return r.Get(ctx, org, id)
}
func (r *Repository) Custody(ctx context.Context, org, id uuid.UUID) ([]CustodyEvent, error) {
	rows, e := r.db.Query(ctx, `SELECT id,job_id,action,from_custodian,to_custodian,note,actor_id,created_at,previous_event_hash,event_hash FROM evidence_custody_events WHERE organization_id=$1 AND job_id=$2 ORDER BY created_at,id`, org, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []CustodyEvent{}
	for rows.Next() {
		var v CustodyEvent
		if e = rows.Scan(&v.ID, &v.JobID, &v.Action, &v.FromCustodian, &v.ToCustodian, &v.Note, &v.ActorID, &v.CreatedAt, &v.PreviousEventHash, &v.EventHash); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
