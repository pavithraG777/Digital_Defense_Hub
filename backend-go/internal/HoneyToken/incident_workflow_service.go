package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrInvalidIncidentStatusTransition = errors.New(
		"invalid incident status transition",
	)
	ErrIncidentInvestigatorRequired = errors.New(
		"incident investigator is required",
	)
	ErrIncidentContainmentSummaryRequired = errors.New(
		"containment summary is required",
	)
	ErrIncidentResolutionSummaryRequired = errors.New(
		"resolution summary is required",
	)
	ErrNoIncidentInvestigationChanges = errors.New(
		"no incident investigation changes supplied",
	)
)

// AssignIncident assigns or reassigns an incident investigator.
func (s *IncidentService) AssignIncident(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	actorUserID uuid.UUID,
	request AssignIncidentRequest,
) (*IncidentResponse, error) {
	if organizationID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidIncidentRequest
	}

	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	investigatorID, err := parseIncidentRequiredUUID(
		request.LeadInvestigatorID,
		"lead investigator ID",
	)
	if err != nil {
		return nil, err
	}

	incident, err := s.repository.Assign(
		ctx,
		organizationID,
		parsedIncidentID,
		investigatorID,
		actorUserID,
	)
	if err != nil {
		return nil, err
	}

	response := buildIncidentResponse(incident)

	return &response, nil
}

// UpdateIncidentStatus validates and applies an incident lifecycle transition.
func (s *IncidentService) UpdateIncidentStatus(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	actorUserID uuid.UUID,
	request UpdateIncidentStatusRequest,
) (*IncidentResponse, error) {
	if organizationID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidIncidentRequest
	}

	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	status := strings.ToUpper(
		strings.TrimSpace(request.Status),
	)

	if !isSupportedIncidentStatus(status) {
		return nil, fmt.Errorf(
			"%w: unsupported incident status",
			ErrInvalidIncidentRequest,
		)
	}

	containmentSummary := normalizeIncidentOptionalText(
		request.ContainmentSummary,
	)
	resolutionSummary := normalizeIncidentOptionalText(
		request.ResolutionSummary,
	)

	currentIncident, err := s.repository.FindByID(
		ctx,
		organizationID,
		parsedIncidentID,
	)
	if err != nil {
		return nil, err
	}

	if currentIncident.Status == status {
		response := buildIncidentResponse(
			currentIncident,
		)

		return &response, nil
	}

	if !isAllowedIncidentStatusTransition(
		currentIncident.Status,
		status,
	) {
		return nil, fmt.Errorf(
			"%w: %s to %s",
			ErrInvalidIncidentStatusTransition,
			currentIncident.Status,
			status,
		)
	}

	if status == IncidentStatusAssigned ||
		status == IncidentStatusInvestigating {
		if currentIncident.LeadInvestigatorID == nil {
			return nil, ErrIncidentInvestigatorRequired
		}
	}

	if status == IncidentStatusContained {
		if containmentSummary == nil &&
			currentIncident.ContainmentSummary == nil {
			return nil,
				ErrIncidentContainmentSummaryRequired
		}
	}

	if status == IncidentStatusResolved {
		if resolutionSummary == nil &&
			currentIncident.ResolutionSummary == nil {
			return nil,
				ErrIncidentResolutionSummaryRequired
		}
	}

	incident, err := s.repository.UpdateStatus(
		ctx,
		organizationID,
		parsedIncidentID,
		status,
		containmentSummary,
		resolutionSummary,
		actorUserID,
	)
	if err != nil {
		return nil, err
	}

	response := buildIncidentResponse(incident)

	return &response, nil
}

// UpdateIncidentInvestigation updates findings, impact and containment data.
func (s *IncidentService) UpdateIncidentInvestigation(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
	actorUserID uuid.UUID,
	request UpdateIncidentInvestigationRequest,
) (*IncidentResponse, error) {
	if organizationID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidIncidentRequest
	}

	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	update := IncidentInvestigationUpdate{
		InitialFindings: normalizeIncidentOptionalText(
			request.InitialFindings,
		),
		RootCause: normalizeIncidentOptionalText(
			request.RootCause,
		),
		ContainmentSummary: normalizeIncidentOptionalText(
			request.ContainmentSummary,
		),
		ResolutionSummary: normalizeIncidentOptionalText(
			request.ResolutionSummary,
		),

		DataExposureSuspected: request.
			DataExposureSuspected,
		RansomwareSuspected: request.
			RansomwareSuspected,
		DeviceIsolated: request.DeviceIsolated,
		EvidencePreserved: request.
			EvidencePreserved,

		AffectedRecordCount: request.
			AffectedRecordCount,
		EstimatedFinancialImpact: request.
			EstimatedFinancialImpact,
	}

	if !hasIncidentInvestigationChanges(update) {
		return nil,
			ErrNoIncidentInvestigationChanges
	}

	incident, err := s.repository.UpdateInvestigation(
		ctx,
		organizationID,
		parsedIncidentID,
		update,
		actorUserID,
	)
	if err != nil {
		return nil, err
	}

	response := buildIncidentResponse(incident)

	return &response, nil
}

func hasIncidentInvestigationChanges(
	update IncidentInvestigationUpdate,
) bool {
	return update.InitialFindings != nil ||
		update.RootCause != nil ||
		update.ContainmentSummary != nil ||
		update.ResolutionSummary != nil ||
		update.DataExposureSuspected != nil ||
		update.RansomwareSuspected != nil ||
		update.DeviceIsolated != nil ||
		update.EvidencePreserved != nil ||
		update.AffectedRecordCount != nil ||
		update.EstimatedFinancialImpact != nil
}

func isAllowedIncidentStatusTransition(
	currentStatus string,
	newStatus string,
) bool {
	switch currentStatus {
	case IncidentStatusOpen:
		return newStatus == IncidentStatusAssigned ||
			newStatus == IncidentStatusInvestigating ||
			newStatus == IncidentStatusCancelled

	case IncidentStatusAssigned:
		return newStatus == IncidentStatusInvestigating ||
			newStatus == IncidentStatusCancelled

	case IncidentStatusInvestigating:
		return newStatus == IncidentStatusContained ||
			newStatus == IncidentStatusResolved ||
			newStatus == IncidentStatusCancelled

	case IncidentStatusContained:
		return newStatus == IncidentStatusEradicated ||
			newStatus == IncidentStatusRecovering ||
			newStatus == IncidentStatusResolved

	case IncidentStatusEradicated:
		return newStatus == IncidentStatusRecovering ||
			newStatus == IncidentStatusResolved

	case IncidentStatusRecovering:
		return newStatus == IncidentStatusContained ||
			newStatus == IncidentStatusResolved

	case IncidentStatusResolved:
		return newStatus == IncidentStatusClosed ||
			newStatus == IncidentStatusReopened

	case IncidentStatusClosed:
		return newStatus == IncidentStatusReopened

	case IncidentStatusReopened:
		return newStatus == IncidentStatusAssigned ||
			newStatus == IncidentStatusInvestigating ||
			newStatus == IncidentStatusCancelled

	case IncidentStatusCancelled:
		return newStatus == IncidentStatusReopened

	default:
		return false
	}
}
