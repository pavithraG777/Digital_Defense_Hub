package forensics

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRepositoryUnavailable  = errors.New("forensics repository is unavailable")
	ErrInvalidForensicsInput  = errors.New("invalid forensics repository input")
	ErrCaseNotFound           = errors.New("forensic case not found")
	ErrAnalysisResultNotFound = errors.New("analysis result not found")
)

// Repository persists forensic cases, evidence, and analysis results.
type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(databasePool *pgxpool.Pool) (*Repository, error) {
	if databasePool == nil {
		return nil, ErrRepositoryUnavailable
	}

	return &Repository{db: databasePool}, nil
}

func (r *Repository) IsAvailable() bool {
	return r != nil && r.db != nil
}

func (r *Repository) EnsureSchema(ctx context.Context) error {
	if !r.IsAvailable() {
		return ErrRepositoryUnavailable
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS forensic_cases (
			id UUID PRIMARY KEY,
			organization_id UUID NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			incident_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS forensic_evidence (
			id UUID PRIMARY KEY,
			case_id UUID NOT NULL REFERENCES forensic_cases(id) ON DELETE CASCADE,
			organization_id UUID NOT NULL,
			evidence_type TEXT NOT NULL,
			source_type TEXT NOT NULL,
			source_path TEXT NOT NULL,
			file_hash TEXT NOT NULL,
			metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS forensic_results (
			id UUID PRIMARY KEY,
			organization_id UUID NOT NULL,
			analysis_job_id UUID NOT NULL,
			case_id UUID NULL REFERENCES forensic_cases(id) ON DELETE SET NULL,
			evidence_id UUID NULL,
			evidence_file_id UUID NULL,
			result_type TEXT NOT NULL,
			result TEXT NOT NULL,
			confidence_score NUMERIC NULL,
			summary TEXT NOT NULL DEFAULT '',
			findings JSONB NOT NULL DEFAULT '[]'::jsonb,
			result_data JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
	}

	for _, query := range queries {
		if _, err := r.db.Exec(ctx, query); err != nil {
			return fmt.Errorf("ensure forensics schema: %w", err)
		}
	}

	return nil
}

func (r *Repository) CreateCase(ctx context.Context, forensicCase *ForensicCase) (*ForensicCase, error) {
	if !r.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if forensicCase == nil {
		return nil, ErrInvalidForensicsInput
	}
	if forensicCase.ID == uuid.Nil {
		forensicCase.ID = uuid.New()
	}
	forensicCase.CreatedAt = time.Now().UTC()
	forensicCase.UpdatedAt = forensicCase.CreatedAt

	incidentIDs, err := json.Marshal(forensicCase.IncidentIDs)
	if err != nil {
		return nil, fmt.Errorf("marshal incident ids: %w", err)
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO forensic_cases (
			id, organization_id, title, description, incident_ids, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`,
		forensicCase.ID,
		forensicCase.OrganizationID,
		forensicCase.Title,
		forensicCase.Description,
		incidentIDs,
		forensicCase.CreatedAt,
		forensicCase.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create forensic case: %w", err)
	}

	return forensicCase, nil
}

func (r *Repository) GetCase(ctx context.Context, caseID uuid.UUID) (*ForensicCase, error) {
	if !r.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if caseID == uuid.Nil {
		return nil, ErrInvalidForensicsInput
	}

	var incidentIDsBytes []byte
	caseRecord := &ForensicCase{}
	if err := r.db.QueryRow(ctx, `
		SELECT id, organization_id, title, description, incident_ids, created_at, updated_at
		FROM forensic_cases
		WHERE id = $1
	`, caseID).Scan(
		&caseRecord.ID,
		&caseRecord.OrganizationID,
		&caseRecord.Title,
		&caseRecord.Description,
		&incidentIDsBytes,
		&caseRecord.CreatedAt,
		&caseRecord.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCaseNotFound
		}
		return nil, fmt.Errorf("get forensic case: %w", err)
	}

	if err := json.Unmarshal(incidentIDsBytes, &caseRecord.IncidentIDs); err != nil {
		return nil, fmt.Errorf("unmarshal incident ids: %w", err)
	}

	return caseRecord, nil
}

func (r *Repository) ListCases(ctx context.Context, organizationID uuid.UUID) ([]*ForensicCase, error) {
	if !r.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if organizationID == uuid.Nil {
		return nil, ErrInvalidForensicsInput
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, organization_id, title, description, incident_ids, created_at, updated_at
		FROM forensic_cases
		WHERE organization_id = $1
		ORDER BY created_at DESC
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list forensic cases: %w", err)
	}
	defer rows.Close()

	var results []*ForensicCase
	for rows.Next() {
		caseRecord := &ForensicCase{}
		var incidentIDsBytes []byte
		if err := rows.Scan(
			&caseRecord.ID,
			&caseRecord.OrganizationID,
			&caseRecord.Title,
			&caseRecord.Description,
			&incidentIDsBytes,
			&caseRecord.CreatedAt,
			&caseRecord.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan forensic case: %w", err)
		}
		if err := json.Unmarshal(incidentIDsBytes, &caseRecord.IncidentIDs); err != nil {
			return nil, fmt.Errorf("unmarshal incident ids: %w", err)
		}
		results = append(results, caseRecord)
	}

	return results, nil
}

func (r *Repository) CreateEvidence(ctx context.Context, evidence *ForensicEvidence) (*ForensicEvidence, error) {
	if !r.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if evidence == nil {
		return nil, ErrInvalidForensicsInput
	}
	if evidence.ID == uuid.Nil {
		evidence.ID = uuid.New()
	}
	if evidence.CreatedAt.IsZero() {
		evidence.CreatedAt = time.Now().UTC()
	}

	metadataBytes, err := json.Marshal(evidence.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence metadata: %w", err)
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO forensic_evidence (
			id, case_id, organization_id, evidence_type, source_type, source_path, file_hash, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		evidence.ID,
		evidence.CaseID,
		evidence.OrganizationID,
		evidence.EvidenceType,
		evidence.SourceType,
		evidence.SourcePath,
		evidence.FileHash,
		metadataBytes,
		evidence.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create forensic evidence: %w", err)
	}

	return evidence, nil
}

func (r *Repository) ListEvidence(ctx context.Context, caseID uuid.UUID) ([]*ForensicEvidence, error) {
	if !r.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if caseID == uuid.Nil {
		return nil, ErrInvalidForensicsInput
	}

	rows, err := r.db.Query(ctx, `
		SELECT id, case_id, organization_id, evidence_type, source_type, source_path, file_hash, metadata, created_at
		FROM forensic_evidence
		WHERE case_id = $1
		ORDER BY created_at DESC
	`, caseID)
	if err != nil {
		return nil, fmt.Errorf("list forensic evidence: %w", err)
	}
	defer rows.Close()

	var results []*ForensicEvidence
	for rows.Next() {
		evidence := &ForensicEvidence{}
		var metadataBytes []byte
		if err := rows.Scan(
			&evidence.ID,
			&evidence.CaseID,
			&evidence.OrganizationID,
			&evidence.EvidenceType,
			&evidence.SourceType,
			&evidence.SourcePath,
			&evidence.FileHash,
			&metadataBytes,
			&evidence.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan forensic evidence: %w", err)
		}
		if err := json.Unmarshal(metadataBytes, &evidence.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal evidence metadata: %w", err)
		}
		results = append(results, evidence)
	}

	return results, nil
}

func (r *Repository) CreateAnalysisResult(ctx context.Context, result *ForensicAnalysisResult) (*ForensicAnalysisResult, error) {
	if !r.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if result == nil {
		return nil, ErrInvalidForensicsInput
	}
	if result.ID == uuid.Nil {
		result.ID = uuid.New()
	}
	result.CreatedAt = time.Now().UTC()
	result.UpdatedAt = result.CreatedAt

	findingsBytes, err := json.Marshal(result.Findings)
	if err != nil {
		return nil, fmt.Errorf("marshal analysis findings: %w", err)
	}
	resultDataBytes, err := json.Marshal(result.ResultData)
	if err != nil {
		return nil, fmt.Errorf("marshal result data: %w", err)
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO forensic_results (
			id, organization_id, analysis_job_id, case_id, evidence_id, evidence_file_id,
			result_type, result, confidence_score, summary, findings, result_data,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`,
		result.ID,
		result.OrganizationID,
		result.AnalysisJobID,
		result.CaseID,
		result.EvidenceID,
		result.EvidenceFileID,
		result.ResultType,
		result.Result,
		result.ConfidenceScore,
		result.Summary,
		findingsBytes,
		resultDataBytes,
		result.CreatedAt,
		result.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create analysis result: %w", err)
	}

	return result, nil
}

func (r *Repository) GetAnalysisResult(ctx context.Context, analysisJobID uuid.UUID) (*ForensicAnalysisResult, error) {
	if !r.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if analysisJobID == uuid.Nil {
		return nil, ErrInvalidForensicsInput
	}

	var findingsBytes []byte
	var resultDataBytes []byte
	result := &ForensicAnalysisResult{}
	if err := r.db.QueryRow(ctx, `
		SELECT id, organization_id, analysis_job_id, case_id, evidence_id, evidence_file_id,
			result_type, result, confidence_score, summary, findings, result_data, created_at, updated_at
		FROM forensic_results
		WHERE analysis_job_id = $1
	`, analysisJobID).Scan(
		&result.ID,
		&result.OrganizationID,
		&result.AnalysisJobID,
		&result.CaseID,
		&result.EvidenceID,
		&result.EvidenceFileID,
		&result.ResultType,
		&result.Result,
		&result.ConfidenceScore,
		&result.Summary,
		&findingsBytes,
		&resultDataBytes,
		&result.CreatedAt,
		&result.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAnalysisResultNotFound
		}
		return nil, fmt.Errorf("get analysis result: %w", err)
	}

	if err := json.Unmarshal(findingsBytes, &result.Findings); err != nil {
		return nil, fmt.Errorf("unmarshal result findings: %w", err)
	}
	if err := json.Unmarshal(resultDataBytes, &result.ResultData); err != nil {
		return nil, fmt.Errorf("unmarshal result data: %w", err)
	}

	return result, nil
}

func (r *Repository) ListAnalysisResults(ctx context.Context, organizationID uuid.UUID, caseID *uuid.UUID) ([]*ForensicAnalysisResult, error) {
	if !r.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if organizationID == uuid.Nil {
		return nil, ErrInvalidForensicsInput
	}

	query := `
		SELECT id, organization_id, analysis_job_id, case_id, evidence_id, evidence_file_id,
			result_type, result, confidence_score, summary, findings, result_data, created_at, updated_at
		FROM forensic_results
		WHERE organization_id = $1`
	if caseID != nil {
		query += " AND case_id = $2"
	}
	query += " ORDER BY created_at DESC"

	var rows pgx.Rows
	var err error
	if caseID != nil {
		rows, err = r.db.Query(ctx, query, organizationID, *caseID)
	} else {
		rows, err = r.db.Query(ctx, query, organizationID)
	}
	if err != nil {
		return nil, fmt.Errorf("list analysis results: %w", err)
	}
	defer rows.Close()

	var results []*ForensicAnalysisResult
	for rows.Next() {
		result := &ForensicAnalysisResult{}
		var findingsBytes []byte
		var resultDataBytes []byte
		if err := rows.Scan(
			&result.ID,
			&result.OrganizationID,
			&result.AnalysisJobID,
			&result.CaseID,
			&result.EvidenceID,
			&result.EvidenceFileID,
			&result.ResultType,
			&result.Result,
			&result.ConfidenceScore,
			&result.Summary,
			&findingsBytes,
			&resultDataBytes,
			&result.CreatedAt,
			&result.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan forensic analysis result: %w", err)
		}
		if err := json.Unmarshal(findingsBytes, &result.Findings); err != nil {
			return nil, fmt.Errorf("unmarshal result findings: %w", err)
		}
		if err := json.Unmarshal(resultDataBytes, &result.ResultData); err != nil {
			return nil, fmt.Errorf("unmarshal result data: %w", err)
		}
		results = append(results, result)
	}

	return results, nil
}
