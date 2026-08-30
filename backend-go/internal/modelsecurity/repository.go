package modelsecurity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrVerificationNotFound = errors.New("model verification not found")

type Verification struct {
	ID                   uuid.UUID               `json:"id"`
	OrganizationID       uuid.UUID               `json:"organization_id"`
	ModelID              string                  `json:"model_id"`
	ModelVersion         string                  `json:"model_version"`
	ExpectedSHA256       string                  `json:"expected_sha256"`
	ObservedSHA256       string                  `json:"observed_sha256"`
	AttestationIssuer    string                  `json:"attestation_issuer,omitempty"`
	AttestationReference string                  `json:"attestation_reference,omitempty"`
	ValidationPassed     bool                    `json:"validation_passed"`
	IntegrityVerified    bool                    `json:"integrity_verified"`
	Status               string                  `json:"status"`
	Assessment           ModelSecurityAssessment `json:"assessment"`
	VerifiedBy           uuid.UUID               `json:"verified_by"`
	VerifiedAt           time.Time               `json:"verified_at"`
}

type VerificationRepository interface {
	Create(context.Context, *Verification) error
	List(context.Context, uuid.UUID, int) ([]Verification, error)
	Get(context.Context, uuid.UUID, uuid.UUID) (*Verification, error)
	Summary(context.Context, uuid.UUID) (IntegritySummary, error)
}

type Repository struct{ db *pgxpool.Pool }

func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func (r *Repository) EnsureSchema(ctx context.Context) error {
	_, err := r.db.Exec(ctx, `CREATE TABLE IF NOT EXISTS model_security_verifications (
		id UUID PRIMARY KEY, organization_id UUID NOT NULL, model_id TEXT NOT NULL,
		model_version TEXT NOT NULL, expected_sha256 CHAR(64) NOT NULL,
		observed_sha256 CHAR(64) NOT NULL, attestation_issuer TEXT,
		attestation_reference TEXT, validation_passed BOOLEAN NOT NULL,
		integrity_verified BOOLEAN NOT NULL, status TEXT NOT NULL,
		risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
		risk_level TEXT NOT NULL, requires_review BOOLEAN NOT NULL,
		risk_flags JSONB NOT NULL DEFAULT '[]'::jsonb, summary TEXT NOT NULL,
		verified_by UUID NOT NULL, verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	); CREATE INDEX IF NOT EXISTS idx_model_security_org_time
	ON model_security_verifications (organization_id, verified_at DESC);`)
	return err
}

func (r *Repository) Create(ctx context.Context, v *Verification) error {
	flags, _ := json.Marshal(v.Assessment.RiskFlags)
	_, err := r.db.Exec(ctx, `INSERT INTO model_security_verifications
	(id,organization_id,model_id,model_version,expected_sha256,observed_sha256,attestation_issuer,attestation_reference,validation_passed,integrity_verified,status,risk_score,risk_level,requires_review,risk_flags,summary,verified_by,verified_at)
	VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		v.ID, v.OrganizationID, v.ModelID, v.ModelVersion, v.ExpectedSHA256, v.ObservedSHA256, v.AttestationIssuer, v.AttestationReference, v.ValidationPassed, v.IntegrityVerified, v.Status, v.Assessment.RiskScore, v.Assessment.RiskLevel, v.Assessment.RequiresReview, flags, v.Assessment.Summary, v.VerifiedBy, v.VerifiedAt)
	return err
}

const selectVerification = `SELECT id,organization_id,model_id,model_version,expected_sha256,observed_sha256,attestation_issuer,attestation_reference,validation_passed,integrity_verified,status,risk_score,risk_level,requires_review,risk_flags,summary,verified_by,verified_at FROM model_security_verifications`

func scanVerification(row pgx.Row) (*Verification, error) {
	v := new(Verification)
	var flags []byte
	err := row.Scan(&v.ID, &v.OrganizationID, &v.ModelID, &v.ModelVersion, &v.ExpectedSHA256, &v.ObservedSHA256, &v.AttestationIssuer, &v.AttestationReference, &v.ValidationPassed, &v.IntegrityVerified, &v.Status, &v.Assessment.RiskScore, &v.Assessment.RiskLevel, &v.Assessment.RequiresReview, &flags, &v.Assessment.Summary, &v.VerifiedBy, &v.VerifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrVerificationNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(flags, &v.Assessment.RiskFlags); err != nil {
		return nil, fmt.Errorf("decode risk flags: %w", err)
	}
	return v, nil
}
func (r *Repository) Get(ctx context.Context, orgID, id uuid.UUID) (*Verification, error) {
	return scanVerification(r.db.QueryRow(ctx, selectVerification+` WHERE organization_id=$1 AND id=$2`, orgID, id))
}
func (r *Repository) List(ctx context.Context, orgID uuid.UUID, limit int) ([]Verification, error) {
	rows, err := r.db.Query(ctx, selectVerification+` WHERE organization_id=$1 ORDER BY verified_at DESC LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Verification, 0)
	for rows.Next() {
		v, err := scanVerification(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *v)
	}
	return result, rows.Err()
}

type IntegritySummary struct {
	Total          int        `json:"total"`
	Verified       int        `json:"verified"`
	Blocked        int        `json:"blocked"`
	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty"`
}

func (r *Repository) Summary(ctx context.Context, orgID uuid.UUID) (s IntegritySummary, err error) {
	err = r.db.QueryRow(ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE status='VERIFIED'),COUNT(*) FILTER(WHERE status='BLOCKED'),MAX(verified_at) FROM model_security_verifications WHERE organization_id=$1`, orgID).Scan(&s.Total, &s.Verified, &s.Blocked, &s.LastVerifiedAt)
	return
}
