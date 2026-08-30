package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type InvestigationCaseService struct{ repository *InvestigationCaseRepository }

func NewInvestigationCaseService(repository *InvestigationCaseRepository) (*InvestigationCaseService, error) {
	if repository == nil {
		return nil, errors.New("investigation case repository is required")
	}
	return &InvestigationCaseService{repository: repository}, nil
}
func (s *InvestigationCaseService) Create(ctx context.Context, orgID, actorID uuid.UUID, request CreateInvestigationCaseRequest) (*InvestigationCaseResponse, error) {
	if orgID == uuid.Nil || actorID == uuid.Nil {
		return nil, ErrInvalidIncidentRequest
	}
	leadID, err := parseIncidentOptionalUUID(request.LeadInvestigatorID, "lead investigator ID")
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	item := &InvestigationCase{ID: uuid.New(), OrganizationID: orgID, CaseNumber: generateCaseNumber(now), Title: strings.TrimSpace(request.Title), Description: normalizeIncidentOptionalText(request.Description), Status: "OPEN", Priority: strings.ToUpper(strings.TrimSpace(request.Priority)), LeadInvestigatorID: leadID, OpenedBy: actorID, OpenedAt: now}
	if item.Priority == "" {
		item.Priority = "MEDIUM"
	}
	if err := s.repository.Create(ctx, item); err != nil {
		return nil, err
	}
	result := buildCaseResponse(item)
	return &result, nil
}
func (s *InvestigationCaseService) Get(ctx context.Context, orgID uuid.UUID, id string) (*InvestigationCaseResponse, error) {
	caseID, err := parseIncidentRequiredUUID(id, "case ID")
	if err != nil {
		return nil, err
	}
	item, err := s.repository.Find(ctx, orgID, caseID)
	if err != nil {
		return nil, err
	}
	result := buildCaseResponse(item)
	return &result, nil
}
func (s *InvestigationCaseService) List(ctx context.Context, orgID uuid.UUID) (*InvestigationCaseListResponse, error) {
	items, total, err := s.repository.List(ctx, orgID)
	if err != nil {
		return nil, err
	}
	result := make([]InvestigationCaseResponse, 0, len(items))
	for i := range items {
		result = append(result, buildCaseResponse(&items[i]))
	}
	return &InvestigationCaseListResponse{Cases: result, Total: total}, nil
}
func (s *InvestigationCaseService) Update(ctx context.Context, orgID uuid.UUID, id string, request UpdateInvestigationCaseRequest) (*InvestigationCaseResponse, error) {
	caseID, err := parseIncidentRequiredUUID(id, "case ID")
	if err != nil {
		return nil, err
	}
	item, err := s.repository.Find(ctx, orgID, caseID)
	if err != nil {
		return nil, err
	}
	if request.Title != nil {
		item.Title = strings.TrimSpace(*request.Title)
	}
	if request.Description != nil {
		item.Description = normalizeIncidentOptionalText(request.Description)
	}
	if request.Priority != nil {
		item.Priority = strings.ToUpper(strings.TrimSpace(*request.Priority))
	}
	if request.Status != nil {
		item.Status = strings.ToUpper(strings.TrimSpace(*request.Status))
		if item.Status == "CLOSED" {
			now := time.Now().UTC()
			item.ClosedAt = &now
		} else {
			item.ClosedAt = nil
		}
	}
	if err := s.repository.Update(ctx, item); err != nil {
		return nil, err
	}
	result := buildCaseResponse(item)
	return &result, nil
}
func (s *InvestigationCaseService) LinkIncident(ctx context.Context, orgID, actorID uuid.UUID, id string, request LinkCaseIncidentRequest) error {
	caseID, err := parseIncidentRequiredUUID(id, "case ID")
	if err != nil {
		return err
	}
	incidentID, err := parseIncidentRequiredUUID(request.IncidentID, "incident ID")
	if err != nil {
		return err
	}
	return s.repository.LinkIncident(ctx, orgID, caseID, incidentID, actorID)
}
func (s *InvestigationCaseService) ListIncidents(ctx context.Context, orgID uuid.UUID, id string) ([]IncidentResponse, error) {
	caseID, err := parseIncidentRequiredUUID(id, "case ID")
	if err != nil {
		return nil, err
	}
	items, err := s.repository.ListIncidents(ctx, orgID, caseID)
	if err != nil {
		return nil, err
	}
	result := make([]IncidentResponse, 0, len(items))
	for i := range items {
		result = append(result, buildIncidentResponse(&items[i]))
	}
	return result, nil
}
func buildCaseResponse(item *InvestigationCase) InvestigationCaseResponse {
	return InvestigationCaseResponse{ID: item.ID.String(), OrganizationID: item.OrganizationID.String(), CaseNumber: item.CaseNumber, Title: item.Title, Description: item.Description, Status: item.Status, Priority: item.Priority, LeadInvestigatorID: incidentOptionalUUIDString(item.LeadInvestigatorID), OpenedBy: item.OpenedBy.String(), OpenedAt: item.OpenedAt, ClosedAt: item.ClosedAt, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}
func generateCaseNumber(now time.Time) string {
	return fmt.Sprintf("DDH-CASE-%s-%s", now.Format("20060102"), strings.ToUpper(uuid.NewString()[:8]))
}
