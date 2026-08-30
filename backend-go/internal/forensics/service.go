package forensics

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Service struct {
	repository *Repository

	mu       sync.RWMutex
	cases    map[uuid.UUID]*ForensicCase
	evidence map[uuid.UUID]*ForensicEvidence
	results  map[uuid.UUID]*ForensicAnalysisResult
}

func NewService(repository *Repository) (*Service, error) {
	if repository == nil || !repository.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}

	return &Service{
		repository: repository,
		cases:      make(map[uuid.UUID]*ForensicCase),
		evidence:   make(map[uuid.UUID]*ForensicEvidence),
		results:    make(map[uuid.UUID]*ForensicAnalysisResult),
	}, nil
}

func (s *Service) CreateCase(
	ctx context.Context,
	organizationID uuid.UUID,
	title string,
	description string,
	incidentIDs []string,
) (*ForensicCase, error) {
	if s == nil || ctx == nil {
		return nil, ErrRepositoryUnavailable
	}
	if organizationID == uuid.Nil {
		return nil, errors.New("organization_id is required")
	}
	if title == "" {
		return nil, errors.New("case title is required")
	}

	forensicCase := &ForensicCase{
		ID:             uuid.New(),
		OrganizationID: organizationID,
		Title:          title,
		Description:    description,
		IncidentIDs:    append([]string(nil), incidentIDs...),
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	if s.repository != nil {
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		return s.repository.CreateCase(ctx, forensicCase)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cases[forensicCase.ID] = forensicCase
	return forensicCase, nil
}

func (s *Service) ListCases(
	ctx context.Context,
	organizationID uuid.UUID,
) ([]*ForensicCase, error) {
	if s == nil || ctx == nil {
		return nil, ErrRepositoryUnavailable
	}
	if organizationID == uuid.Nil {
		return nil, errors.New("organization_id is required")
	}

	if s.repository != nil {
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		return s.repository.ListCases(ctx, organizationID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*ForensicCase, 0, len(s.cases))
	for _, item := range s.cases {
		if item.OrganizationID == organizationID {
			results = append(results, item)
		}
	}
	return results, nil
}

func (s *Service) GetCase(
	ctx context.Context,
	caseID uuid.UUID,
) (*ForensicCase, error) {
	if s == nil || ctx == nil {
		return nil, ErrRepositoryUnavailable
	}
	if caseID == uuid.Nil {
		return nil, errors.New("case_id is required")
	}

	if s.repository != nil {
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		return s.repository.GetCase(ctx, caseID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	caseRecord, ok := s.cases[caseID]
	if !ok {
		return nil, ErrCaseNotFound
	}
	return caseRecord, nil
}

func (s *Service) AddEvidence(
	ctx context.Context,
	evidence *ForensicEvidence,
) (*ForensicEvidence, error) {
	if s == nil || ctx == nil {
		return nil, ErrRepositoryUnavailable
	}
	if evidence == nil {
		return nil, errors.New("evidence is required")
	}
	if evidence.CaseID == uuid.Nil || evidence.OrganizationID == uuid.Nil {
		return nil, errors.New("case_id and organization_id are required")
	}
	if evidence.EvidenceType == "" || evidence.SourceType == "" || evidence.SourcePath == "" {
		return nil, errors.New("evidence_type, source_type, and source_path are required")
	}

	evidence.ID = uuid.New()
	evidence.CreatedAt = time.Now().UTC()

	if s.repository != nil {
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		return s.repository.CreateEvidence(ctx, evidence)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.evidence[evidence.ID] = evidence
	return evidence, nil
}

func (s *Service) ListEvidence(
	ctx context.Context,
	caseID uuid.UUID,
) ([]*ForensicEvidence, error) {
	if s == nil || ctx == nil {
		return nil, ErrRepositoryUnavailable
	}
	if caseID == uuid.Nil {
		return nil, errors.New("case_id is required")
	}

	if s.repository != nil {
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		return s.repository.ListEvidence(ctx, caseID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*ForensicEvidence, 0, len(s.evidence))
	for _, item := range s.evidence {
		if item.CaseID == caseID {
			results = append(results, item)
		}
	}
	return results, nil
}

func (s *Service) CreateAnalysisResult(
	ctx context.Context,
	result *ForensicAnalysisResult,
) (*ForensicAnalysisResult, error) {
	if s == nil || ctx == nil {
		return nil, ErrRepositoryUnavailable
	}
	if result == nil {
		return nil, errors.New("analysis result is required")
	}
	if result.OrganizationID == uuid.Nil || result.AnalysisJobID == uuid.Nil || result.ResultType == "" || result.Result == "" {
		return nil, errors.New("organization_id, analysis_job_id, result_type, and result are required")
	}

	result.ID = uuid.New()
	result.CreatedAt = time.Now().UTC()
	result.UpdatedAt = result.CreatedAt

	if s.repository != nil {
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		return s.repository.CreateAnalysisResult(ctx, result)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[result.ID] = result
	return result, nil
}

func (s *Service) GetAnalysisResult(
	ctx context.Context,
	analysisJobID uuid.UUID,
) (*ForensicAnalysisResult, error) {
	if s == nil || ctx == nil {
		return nil, ErrRepositoryUnavailable
	}
	if analysisJobID == uuid.Nil {
		return nil, errors.New("analysis_job_id is required")
	}

	if s.repository != nil {
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		return s.repository.GetAnalysisResult(ctx, analysisJobID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, item := range s.results {
		if item.AnalysisJobID == analysisJobID {
			return item, nil
		}
	}
	return nil, ErrAnalysisResultNotFound
}

func (s *Service) ListAnalysisResults(
	ctx context.Context,
	organizationID uuid.UUID,
	caseID *uuid.UUID,
) ([]*ForensicAnalysisResult, error) {
	if s == nil || ctx == nil {
		return nil, ErrRepositoryUnavailable
	}
	if organizationID == uuid.Nil {
		return nil, errors.New("organization_id is required")
	}

	if s.repository != nil {
		if err := s.repository.EnsureSchema(ctx); err != nil {
			return nil, err
		}
		return s.repository.ListAnalysisResults(ctx, organizationID, caseID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*ForensicAnalysisResult, 0, len(s.results))
	for _, item := range s.results {
		if item.OrganizationID != organizationID {
			continue
		}
		if caseID != nil && (item.CaseID == nil || *item.CaseID != *caseID) {
			continue
		}
		results = append(results, item)
	}
	return results, nil
}
