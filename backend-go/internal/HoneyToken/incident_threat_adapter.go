package honeytoken

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// CreateFromThreatResponse converts the safe Threat Engine response into the
// internal threat model required by the Incident Automation Service.
func (s *IncidentAutomationService) CreateFromThreatResponse(
	ctx context.Context,
	response *ThreatResponse,
) (*IncidentAutomationResult, error) {
	if response == nil {
		return nil, errors.New(
			"threat response is required",
		)
	}

	threatID, err := uuid.Parse(response.ID)
	if err != nil || threatID == uuid.Nil {
		return nil, errors.New(
			"threat response contains an invalid threat ID",
		)
	}

	organizationID, err := uuid.Parse(
		response.OrganizationID,
	)
	if err != nil || organizationID == uuid.Nil {
		return nil, errors.New(
			"threat response contains an invalid organization ID",
		)
	}

	departmentID, err := incidentThreatOptionalUUID(
		response.DepartmentID,
	)
	if err != nil {
		return nil, err
	}

	threat := &Threat{
		ID:             threatID,
		OrganizationID: organizationID,
		DepartmentID:   departmentID,

		ThreatSequence: response.ThreatSequence,
		ThreatCode:     response.ThreatCode,
		CorrelationKey: response.CorrelationKey,

		ThreatType:      response.ThreatType,
		ThreatCategory:  response.ThreatCategory,
		DetectionMethod: response.DetectionMethod,
		Title:           response.Title,
		Description:     response.Description,

		Severity:        response.Severity,
		ThreatScore:     response.ThreatScore,
		ConfidenceScore: response.ConfidenceScore,
		Classification:  response.Classification,
		Status:          response.Status,

		EventCount:        response.EventCount,
		AffectedFileCount: response.AffectedFileCount,

		FirstDetectedAt: response.FirstDetectedAt,
		LastDetectedAt:  response.LastDetectedAt,

		ProcessName:      response.ProcessName,
		ProcessID:        response.ProcessID,
		ProcessPath:      response.ProcessPath,
		DeviceName:       response.DeviceName,
		DeviceIdentifier: response.DeviceIdentifier,
		SourceIPAddress:  response.SourceIPAddress,

		Indicators:         response.Indicators,
		RiskFactors:        response.RiskFactors,
		EvidenceSummary:    response.EvidenceSummary,
		RecommendedActions: response.RecommendedActions,
		ContainmentActions: response.ContainmentActions,

		CreatedAt: response.CreatedAt,
		UpdatedAt: response.UpdatedAt,
	}

	return s.CreateFromThreat(
		ctx,
		threat,
	)
}

func incidentThreatOptionalUUID(
	value *string,
) (*uuid.UUID, error) {
	if value == nil || *value == "" {
		return nil, nil
	}

	parsedValue, err := uuid.Parse(*value)
	if err != nil || parsedValue == uuid.Nil {
		return nil, errors.New(
			"threat response contains an invalid related UUID",
		)
	}

	return &parsedValue, nil
}
