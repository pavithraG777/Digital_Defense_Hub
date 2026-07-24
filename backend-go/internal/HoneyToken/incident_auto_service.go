package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// IncidentAutomationResult represents automatic Threat-to-Incident
// processing.
type IncidentAutomationResult struct {
	IncidentCreated bool              `json:"incident_created"`
	Incident        *IncidentResponse `json:"incident,omitempty"`
	Reason          string            `json:"reason"`
}

// IncidentAutomationService creates incidents from eligible threats.
type IncidentAutomationService struct {
	repository *IncidentRepository
}

func NewIncidentAutomationService(
	repository *IncidentRepository,
) (*IncidentAutomationService, error) {
	if repository == nil {
		return nil, errors.New(
			"incident repository is required",
		)
	}

	return &IncidentAutomationService{
		repository: repository,
	}, nil
}

// CreateFromThreat creates one idempotent incident for an eligible threat.
func (s *IncidentAutomationService) CreateFromThreat(
	ctx context.Context,
	threat *Threat,
) (*IncidentAutomationResult, error) {
	if threat == nil ||
		threat.ID == uuid.Nil ||
		threat.OrganizationID == uuid.Nil {
		return nil, errors.New(
			"valid threat is required",
		)
	}

	existingIncident, err :=
		s.repository.FindByThreatID(
			ctx,
			threat.OrganizationID,
			threat.ID,
		)
	if err == nil {
		response := buildIncidentResponse(
			existingIncident,
		)

		return &IncidentAutomationResult{
			IncidentCreated: false,
			Incident:        &response,
			Reason:          "threat is already linked to an incident",
		}, nil
	}

	if !errors.Is(err, ErrIncidentNotFound) {
		return nil, err
	}

	eligible, reason :=
		isThreatEligibleForIncident(threat)

	if !eligible {
		return &IncidentAutomationResult{
			IncidentCreated: false,
			Reason:          reason,
		}, nil
	}

	now := time.Now().UTC()
	incidentID := uuid.New()
	affectedRecordCount := int64(
		threat.AffectedFileCount,
	)

	description := buildAutomatedIncidentDescription(
		threat,
	)
	initialFindings := fmt.Sprintf(
		"Automatically generated from threat %s. "+
			"Threat score: %d. Classification: %s. "+
			"Detection method: %s.",
		threat.ThreatCode,
		threat.ThreatScore,
		threat.Classification,
		threat.DetectionMethod,
	)

	incident := &Incident{
		ID:             incidentID,
		OrganizationID: threat.OrganizationID,
		DepartmentID:   threat.DepartmentID,

		IncidentNumber: generateIncidentNumber(
			incidentID,
			now,
		),
		IncidentTitle: buildAutomatedIncidentTitle(
			threat,
		),
		Description: &description,
		IncidentCategory: mapThreatToIncidentCategory(
			threat,
		),
		Severity: threat.Severity,
		Priority: mapThreatToIncidentPriority(
			threat,
		),
		Status: IncidentStatusOpen,
		DetectionSource: mapThreatToIncidentDetectionSource(
			threat,
		),

		AffectedDeviceName: threat.DeviceName,
		AffectedDeviceIdentifier: threat.
			DeviceIdentifier,

		DataExposureSuspected: isThreatDataExposureSuspected(
			threat,
		),
		RansomwareSuspected: isThreatRansomwareSuspected(
			threat,
		),
		DeviceIsolated:    false,
		EvidencePreserved: false,

		AffectedRecordCount: &affectedRecordCount,
		InitialFindings:     &initialFindings,

		DetectedAt: threat.FirstDetectedAt,
		ReportedAt: now,
	}

	err = s.repository.Create(
		ctx,
		incident,
		&threat.ID,
		nil,
	)
	if errors.Is(
		err,
		ErrIncidentThreatAlreadyLinked,
	) {
		existingIncident, findErr :=
			s.repository.FindByThreatID(
				ctx,
				threat.OrganizationID,
				threat.ID,
			)
		if findErr != nil {
			return nil, findErr
		}

		response := buildIncidentResponse(
			existingIncident,
		)

		return &IncidentAutomationResult{
			IncidentCreated: false,
			Incident:        &response,
			Reason:          "threat was concurrently linked to an incident",
		}, nil
	}
	if err != nil {
		return nil, err
	}

	response := buildIncidentResponse(incident)

	return &IncidentAutomationResult{
		IncidentCreated: true,
		Incident:        &response,
		Reason:          "eligible threat escalated to incident",
	}, nil
}

func isThreatEligibleForIncident(
	threat *Threat,
) (bool, string) {
	switch threat.Status {
	case ThreatStatusFalsePositive,
		ThreatStatusResolved,
		ThreatStatusArchived:
		return false,
			"threat status is not eligible for incident creation"
	}

	if threat.Classification ==
		ThreatClassificationLikelyBenign {
		return false,
			"likely benign threat does not require an incident"
	}

	highRiskType := false

	switch threat.ThreatType {
	case ThreatTypeHoneytokenAccess,
		ThreatTypeCanaryTriggered,
		ThreatTypeMassFileModification,
		ThreatTypeMassFileRename,
		ThreatTypeMassFileDeletion,
		ThreatTypeRansomwareActivity,
		ThreatTypeUnauthorizedAccess,
		ThreatTypeSuspiciousProcess,
		ThreatTypeHashMismatch,
		ThreatTypePermissionAbuse:
		highRiskType = true
	}

	if threat.Severity == ThreatLevelCritical {
		return true,
			"critical threat requires incident response"
	}

	if threat.ThreatScore >=
		ThreatScoreCriticalThreshold {
		return true,
			"threat score reached critical threshold"
	}

	if highRiskType &&
		threat.Severity == ThreatLevelHigh &&
		(threat.Classification ==
			ThreatClassificationMalicious ||
			threat.Classification ==
				ThreatClassificationLikelyMalicious) {
		return true,
			"high-risk malicious threat requires incident response"
	}

	return false,
		"threat does not meet automatic incident threshold"
}

func buildAutomatedIncidentTitle(
	threat *Threat,
) string {
	title := strings.TrimSpace(threat.Title)

	if title == "" {
		title = strings.ReplaceAll(
			threat.ThreatType,
			"_",
			" ",
		)
	}

	return "Automated Incident: " + title
}

func buildAutomatedIncidentDescription(
	threat *Threat,
) string {
	if threat.Description != nil &&
		strings.TrimSpace(*threat.Description) != "" {
		return strings.TrimSpace(
			*threat.Description,
		)
	}

	return fmt.Sprintf(
		"Security threat %s was automatically escalated "+
			"for incident investigation.",
		threat.ThreatCode,
	)
}

func mapThreatToIncidentCategory(
	threat *Threat,
) string {
	switch threat.ThreatType {
	case ThreatTypeHoneytokenAccess:
		return IncidentCategoryHoneytokenTrigger

	case ThreatTypeCanaryTriggered:
		return IncidentCategoryCanaryFileTrigger

	case ThreatTypeMassFileModification,
		ThreatTypeMassFileRename,
		ThreatTypeMassFileDeletion,
		ThreatTypeRansomwareActivity:
		return IncidentCategoryRansomware

	case ThreatTypeUnauthorizedAccess,
		ThreatTypePermissionAbuse:
		return IncidentCategoryUnauthorizedAccess

	case ThreatTypeSuspiciousProcess:
		return IncidentCategoryMalware

	case ThreatTypeHashMismatch,
		ThreatTypeFileTampering:
		return IncidentCategorySystemAnomaly

	default:
		return IncidentCategoryOther
	}
}

func mapThreatToIncidentPriority(
	threat *Threat,
) string {
	switch threat.Severity {
	case ThreatLevelCritical:
		return IncidentPriorityUrgent

	case ThreatLevelHigh:
		return IncidentPriorityHigh

	case ThreatLevelMedium:
		return IncidentPriorityMedium

	default:
		return IncidentPriorityLow
	}
}

func mapThreatToIncidentDetectionSource(
	threat *Threat,
) string {
	switch threat.ThreatType {
	case ThreatTypeHoneytokenAccess:
		return IncidentDetectionSourceHoneytoken

	case ThreatTypeCanaryTriggered:
		return IncidentDetectionSourceCanaryFile

	case ThreatTypeMassFileModification,
		ThreatTypeMassFileRename,
		ThreatTypeMassFileDeletion,
		ThreatTypeRansomwareActivity,
		ThreatTypeFileTampering,
		ThreatTypeHashMismatch:
		return IncidentDetectionSourceFileMonitoring

	default:
		return IncidentDetectionSourceSecurityAlert
	}
}

func isThreatRansomwareSuspected(
	threat *Threat,
) bool {
	switch threat.ThreatType {
	case ThreatTypeMassFileModification,
		ThreatTypeMassFileRename,
		ThreatTypeMassFileDeletion,
		ThreatTypeRansomwareActivity:
		return true

	default:
		return false
	}
}

func isThreatDataExposureSuspected(
	threat *Threat,
) bool {
	switch threat.ThreatType {
	case ThreatTypeUnauthorizedAccess,
		ThreatTypeHoneytokenAccess,
		ThreatTypePermissionAbuse:
		return true

	default:
		return false
	}
}
