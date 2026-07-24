package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidThreatRequest    = errors.New("invalid threat request")
	ErrInvalidThreatTransition = errors.New("invalid threat status transition")
)

// ThreatService provides organization-scoped threat operations.
type ThreatService struct {
	repository *ThreatRepository
}

func NewThreatService(
	repository *ThreatRepository,
) (*ThreatService, error) {
	if repository == nil {
		return nil, errors.New("threat repository is required")
	}

	return &ThreatService{
		repository: repository,
	}, nil
}

// GetThreat returns a threat with all correlated file events.
func (s *ThreatService) GetThreat(
	ctx context.Context,
	organizationID string,
	threatID string,
) (*ThreatResponse, error) {
	organizationUUID, err := parseThreatUUID(
		organizationID,
		"organization_id",
	)
	if err != nil {
		return nil, err
	}

	threatUUID, err := parseThreatUUID(
		threatID,
		"threat_id",
	)
	if err != nil {
		return nil, err
	}

	threat, err := s.repository.FindByID(
		ctx,
		organizationUUID,
		threatUUID,
	)
	if err != nil {
		return nil, err
	}

	relations, err := s.repository.ListFileEvents(
		ctx,
		organizationUUID,
		threatUUID,
	)
	if err != nil {
		return nil, err
	}

	response := threatToResponse(threat)
	response.FileEvents = threatFileEventsToResponse(relations)

	return &response, nil
}

// ListThreats returns a validated, paginated organization threat list.
func (s *ThreatService) ListThreats(
	ctx context.Context,
	organizationID string,
	query ThreatListQuery,
) (*ThreatListResponse, error) {
	organizationUUID, err := parseThreatUUID(
		organizationID,
		"organization_id",
	)
	if err != nil {
		return nil, err
	}

	page := query.Page
	if page == 0 {
		page = 1
	}

	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = 20
	}

	if page < 1 {
		return nil, fmt.Errorf(
			"%w: page must be at least 1",
			ErrInvalidThreatRequest,
		)
	}

	if pageSize < 1 || pageSize > 100 {
		return nil, fmt.Errorf(
			"%w: page_size must be between 1 and 100",
			ErrInvalidThreatRequest,
		)
	}

	filter := ThreatFilter{
		OrganizationID: organizationUUID,
		ThreatType: strings.ToUpper(
			strings.TrimSpace(query.ThreatType),
		),
		Category: strings.ToUpper(
			strings.TrimSpace(query.Category),
		),
		Severity: strings.ToUpper(
			strings.TrimSpace(query.Severity),
		),
		Classification: strings.ToUpper(
			strings.TrimSpace(query.Classification),
		),
		Status: strings.ToUpper(
			strings.TrimSpace(query.Status),
		),
		DetectionMethod: strings.ToUpper(
			strings.TrimSpace(query.DetectionMethod),
		),
		Search: strings.TrimSpace(query.Search),
		Limit:  pageSize,
		Offset: (page - 1) * pageSize,
	}

	if query.DepartmentID != "" {
		departmentID, parseErr := parseThreatUUID(
			query.DepartmentID,
			"department_id",
		)
		if parseErr != nil {
			return nil, parseErr
		}

		filter.DepartmentID = &departmentID
	}

	if filter.ThreatType != "" &&
		!isValidThreatType(filter.ThreatType) {
		return nil, fmt.Errorf(
			"%w: unsupported threat_type",
			ErrInvalidThreatRequest,
		)
	}

	if filter.Category != "" &&
		!isValidThreatCategory(filter.Category) {
		return nil, fmt.Errorf(
			"%w: unsupported category",
			ErrInvalidThreatRequest,
		)
	}

	if filter.Severity != "" &&
		!isValidThreatSeverity(filter.Severity) {
		return nil, fmt.Errorf(
			"%w: unsupported severity",
			ErrInvalidThreatRequest,
		)
	}

	if filter.Classification != "" &&
		!isValidThreatClassification(filter.Classification) {
		return nil, fmt.Errorf(
			"%w: unsupported classification",
			ErrInvalidThreatRequest,
		)
	}

	if filter.Status != "" &&
		!isValidThreatStatus(filter.Status) {
		return nil, fmt.Errorf(
			"%w: unsupported status",
			ErrInvalidThreatRequest,
		)
	}

	if filter.DetectionMethod != "" &&
		!isValidThreatDetectionMethod(filter.DetectionMethod) {
		return nil, fmt.Errorf(
			"%w: unsupported detection_method",
			ErrInvalidThreatRequest,
		)
	}

	if query.From != "" {
		from, parseErr := parseThreatTime(query.From, "from")
		if parseErr != nil {
			return nil, parseErr
		}

		filter.From = &from
	}

	if query.To != "" {
		to, parseErr := parseThreatTime(query.To, "to")
		if parseErr != nil {
			return nil, parseErr
		}

		filter.To = &to
	}

	if filter.From != nil &&
		filter.To != nil &&
		filter.To.Before(*filter.From) {
		return nil, fmt.Errorf(
			"%w: to must be after from",
			ErrInvalidThreatRequest,
		)
	}

	threats, total, err := s.repository.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	responses := make([]ThreatResponse, 0, len(threats))
	for index := range threats {
		responses = append(
			responses,
			threatToResponse(&threats[index]),
		)
	}

	totalPages := 0
	if total > 0 {
		totalPages = int(
			(total + int64(pageSize) - 1) / int64(pageSize),
		)
	}

	return &ThreatListResponse{
		Threats:    responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// UpdateThreatStatus applies a validated threat lifecycle transition.
func (s *ThreatService) UpdateThreatStatus(
	ctx context.Context,
	organizationID string,
	threatID string,
	actorID string,
	request UpdateThreatStatusRequest,
) (*ThreatResponse, error) {
	organizationUUID, err := parseThreatUUID(
		organizationID,
		"organization_id",
	)
	if err != nil {
		return nil, err
	}

	threatUUID, err := parseThreatUUID(
		threatID,
		"threat_id",
	)
	if err != nil {
		return nil, err
	}

	actorUUID, err := parseThreatUUID(actorID, "actor_id")
	if err != nil {
		return nil, err
	}

	requestedStatus := strings.ToUpper(
		strings.TrimSpace(request.Status),
	)
	if !isValidThreatStatus(requestedStatus) {
		return nil, fmt.Errorf(
			"%w: unsupported status",
			ErrInvalidThreatRequest,
		)
	}

	currentThreat, err := s.repository.FindByID(
		ctx,
		organizationUUID,
		threatUUID,
	)
	if err != nil {
		return nil, err
	}

	if currentThreat.Status != requestedStatus &&
		!isThreatTransitionAllowed(
			currentThreat.Status,
			requestedStatus,
		) {
		return nil, fmt.Errorf(
			"%w: %s to %s",
			ErrInvalidThreatTransition,
			currentThreat.Status,
			requestedStatus,
		)
	}

	resolutionNotes := normalizeThreatOptionalText(
		request.ResolutionNotes,
	)

	if (requestedStatus == ThreatStatusResolved ||
		requestedStatus == ThreatStatusFalsePositive) &&
		resolutionNotes == nil {
		return nil, fmt.Errorf(
			"%w: resolution_notes is required for %s status",
			ErrInvalidThreatRequest,
			requestedStatus,
		)
	}

	updatedThreat, err := s.repository.UpdateStatus(
		ctx,
		organizationUUID,
		threatUUID,
		requestedStatus,
		resolutionNotes,
		actorUUID,
	)
	if err != nil {
		return nil, err
	}

	relations, err := s.repository.ListFileEvents(
		ctx,
		organizationUUID,
		threatUUID,
	)
	if err != nil {
		return nil, err
	}

	response := threatToResponse(updatedThreat)
	response.FileEvents = threatFileEventsToResponse(relations)

	return &response, nil
}

// AssignThreat assigns an organization threat to an investigator.
func (s *ThreatService) AssignThreat(
	ctx context.Context,
	organizationID string,
	threatID string,
	request AssignThreatRequest,
) (*ThreatResponse, error) {
	organizationUUID, err := parseThreatUUID(
		organizationID,
		"organization_id",
	)
	if err != nil {
		return nil, err
	}

	threatUUID, err := parseThreatUUID(
		threatID,
		"threat_id",
	)
	if err != nil {
		return nil, err
	}

	assignedTo, err := parseThreatUUID(
		request.AssignedTo,
		"assigned_to",
	)
	if err != nil {
		return nil, err
	}

	updatedThreat, err := s.repository.Assign(
		ctx,
		organizationUUID,
		threatUUID,
		assignedTo,
	)
	if err != nil {
		return nil, err
	}

	response := threatToResponse(updatedThreat)

	return &response, nil
}

func parseThreatUUID(
	value string,
	fieldName string,
) (uuid.UUID, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil || parsed == uuid.Nil {
		return uuid.Nil, fmt.Errorf(
			"%w: %s must be a valid UUID",
			ErrInvalidThreatRequest,
			fieldName,
		)
	}

	return parsed, nil
}

func parseThreatTime(
	value string,
	fieldName string,
) (time.Time, error) {
	parsed, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(value),
	)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"%w: %s must use RFC3339 format",
			ErrInvalidThreatRequest,
			fieldName,
		)
	}

	return parsed, nil
}

func normalizeThreatOptionalText(value *string) *string {
	if value == nil {
		return nil
	}

	normalized := strings.TrimSpace(*value)
	if normalized == "" {
		return nil
	}

	return &normalized
}

func isValidThreatType(value string) bool {
	switch value {
	case ThreatTypeHoneytokenAccess,
		ThreatTypeCanaryTriggered,
		ThreatTypeFileTampering,
		ThreatTypeMassFileModification,
		ThreatTypeMassFileRename,
		ThreatTypeMassFileDeletion,
		ThreatTypeRansomwareActivity,
		ThreatTypeUnauthorizedAccess,
		ThreatTypeSuspiciousProcess,
		ThreatTypeHashMismatch,
		ThreatTypePermissionAbuse,
		ThreatTypeCustom:
		return true
	default:
		return false
	}
}

func isValidThreatCategory(value string) bool {
	switch value {
	case ThreatCategoryDeception,
		ThreatCategoryRansomware,
		ThreatCategoryIntegrity,
		ThreatCategoryAccessControl,
		ThreatCategoryMalware,
		ThreatCategoryBehaviourAnomaly,
		ThreatCategoryUnknown:
		return true
	default:
		return false
	}
}

func isValidThreatSeverity(value string) bool {
	switch value {
	case ThreatLevelLow,
		ThreatLevelMedium,
		ThreatLevelHigh,
		ThreatLevelCritical:
		return true
	default:
		return false
	}
}

func isValidThreatClassification(value string) bool {
	switch value {
	case ThreatClassificationUnknown,
		ThreatClassificationLikelyBenign,
		ThreatClassificationSuspicious,
		ThreatClassificationLikelyMalicious,
		ThreatClassificationMalicious:
		return true
	default:
		return false
	}
}

func isValidThreatStatus(value string) bool {
	switch value {
	case ThreatStatusDetected,
		ThreatStatusAnalyzing,
		ThreatStatusConfirmed,
		ThreatStatusFalsePositive,
		ThreatStatusMitigated,
		ThreatStatusEscalated,
		ThreatStatusResolved,
		ThreatStatusArchived:
		return true
	default:
		return false
	}
}

func isValidThreatDetectionMethod(value string) bool {
	switch value {
	case "RULE_BASED",
		"SIGNATURE_BASED",
		"BEHAVIOUR_BASED",
		"AI_BASED",
		"HYBRID":
		return true
	default:
		return false
	}
}

func isThreatTransitionAllowed(
	currentStatus string,
	requestedStatus string,
) bool {
	allowedTransitions := map[string]map[string]struct{}{
		ThreatStatusDetected: {
			ThreatStatusAnalyzing:     {},
			ThreatStatusConfirmed:     {},
			ThreatStatusFalsePositive: {},
			ThreatStatusEscalated:     {},
			ThreatStatusArchived:      {},
		},
		ThreatStatusAnalyzing: {
			ThreatStatusConfirmed:     {},
			ThreatStatusFalsePositive: {},
			ThreatStatusEscalated:     {},
			ThreatStatusArchived:      {},
		},
		ThreatStatusConfirmed: {
			ThreatStatusMitigated:     {},
			ThreatStatusEscalated:     {},
			ThreatStatusFalsePositive: {},
		},
		ThreatStatusMitigated: {
			ThreatStatusResolved:  {},
			ThreatStatusEscalated: {},
		},
		ThreatStatusEscalated: {
			ThreatStatusAnalyzing: {},
			ThreatStatusConfirmed: {},
			ThreatStatusMitigated: {},
			ThreatStatusResolved:  {},
		},
		ThreatStatusResolved: {
			ThreatStatusArchived:  {},
			ThreatStatusEscalated: {},
		},
		ThreatStatusFalsePositive: {
			ThreatStatusAnalyzing: {},
			ThreatStatusArchived:  {},
		},
		ThreatStatusArchived: {},
	}

	nextStatuses, exists := allowedTransitions[currentStatus]
	if !exists {
		return false
	}

	_, allowed := nextStatuses[requestedStatus]

	return allowed
}

func threatToResponse(threat *Threat) ThreatResponse {
	return ThreatResponse{
		ID:                 threat.ID.String(),
		ThreatSequence:     threat.ThreatSequence,
		ThreatCode:         threat.ThreatCode,
		CorrelationKey:     threat.CorrelationKey,
		OrganizationID:     threat.OrganizationID.String(),
		DepartmentID:       threatUUIDPointerToString(threat.DepartmentID),
		PrimaryFileEventID: threatUUIDPointerToString(threat.PrimaryFileEventID),
		MonitoringRuleID:   threatUUIDPointerToString(threat.MonitoringRuleID),
		ProtectedFileID:    threatUUIDPointerToString(threat.ProtectedFileID),
		HoneytokenID:       threatUUIDPointerToString(threat.HoneytokenID),
		CanaryFileID:       threatUUIDPointerToString(threat.CanaryFileID),
		ThreatType:         threat.ThreatType,
		ThreatCategory:     threat.ThreatCategory,
		DetectionMethod:    threat.DetectionMethod,
		Title:              threat.Title,
		Description:        threat.Description,
		Severity:           threat.Severity,
		ThreatScore:        threat.ThreatScore,
		ConfidenceScore:    threat.ConfidenceScore,
		Classification:     threat.Classification,
		Status:             threat.Status,
		EventCount:         threat.EventCount,
		AffectedFileCount:  threat.AffectedFileCount,
		FirstDetectedAt:    threat.FirstDetectedAt,
		LastDetectedAt:     threat.LastDetectedAt,
		ProcessName:        threat.ProcessName,
		ProcessID:          threat.ProcessID,
		ProcessPath:        threat.ProcessPath,
		DeviceName:         threat.DeviceName,
		DeviceIdentifier:   threat.DeviceIdentifier,
		SourceIPAddress:    threat.SourceIPAddress,
		Indicators:         threat.Indicators,
		RiskFactors:        threat.RiskFactors,
		EvidenceSummary:    threat.EvidenceSummary,
		RecommendedActions: threat.RecommendedActions,
		ContainmentActions: threat.ContainmentActions,
		ResolutionNotes:    threat.ResolutionNotes,
		AssignedTo:         threatUUIDPointerToString(threat.AssignedTo),
		ConfirmedBy:        threatUUIDPointerToString(threat.ConfirmedBy),
		ResolvedBy:         threatUUIDPointerToString(threat.ResolvedBy),
		ConfirmedAt:        threat.ConfirmedAt,
		MitigatedAt:        threat.MitigatedAt,
		ResolvedAt:         threat.ResolvedAt,
		CreatedAt:          threat.CreatedAt,
		UpdatedAt:          threat.UpdatedAt,
	}
}

func threatFileEventsToResponse(
	relations []ThreatFileEvent,
) []ThreatFileEventResponse {
	responses := make(
		[]ThreatFileEventResponse,
		0,
		len(relations),
	)

	for _, relation := range relations {
		responses = append(
			responses,
			ThreatFileEventResponse{
				FileEventID:  relation.FileEventID.String(),
				RelationType: relation.RelationType,
				CreatedAt:    relation.CreatedAt,
			},
		)
	}

	return responses
}

func threatUUIDPointerToString(value *uuid.UUID) *string {
	if value == nil {
		return nil
	}

	stringValue := value.String()

	return &stringValue
}
