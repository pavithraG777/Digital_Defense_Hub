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
	ErrInvalidIncidentRequest = errors.New(
		"invalid incident request",
	)
	ErrIncidentFutureDetectionTime = errors.New(
		"incident detection time is in the future",
	)
)

// IncidentService manages organization-scoped incident operations.
type IncidentService struct {
	repository *IncidentRepository
}

func NewIncidentService(
	repository *IncidentRepository,
) (*IncidentService, error) {
	if repository == nil {
		return nil, errors.New(
			"incident repository is required",
		)
	}

	return &IncidentService{
		repository: repository,
	}, nil
}

// CreateIncident creates a manually reported security incident.
func (s *IncidentService) CreateIncident(
	ctx context.Context,
	organizationID uuid.UUID,
	reportedBy uuid.UUID,
	request CreateIncidentRequest,
) (*IncidentResponse, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if reportedBy == uuid.Nil {
		return nil, errors.New(
			"incident reporter ID is required",
		)
	}

	request.IncidentTitle = strings.TrimSpace(
		request.IncidentTitle,
	)
	request.IncidentCategory = strings.ToUpper(
		strings.TrimSpace(request.IncidentCategory),
	)
	request.Severity = strings.ToUpper(
		strings.TrimSpace(request.Severity),
	)
	request.Priority = strings.ToUpper(
		strings.TrimSpace(request.Priority),
	)
	request.DetectionSource = strings.ToUpper(
		strings.TrimSpace(request.DetectionSource),
	)

	if request.IncidentTitle == "" {
		return nil, fmt.Errorf(
			"%w: incident title is required",
			ErrInvalidIncidentRequest,
		)
	}

	if !isSupportedIncidentCategory(
		request.IncidentCategory,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported incident category",
			ErrInvalidIncidentRequest,
		)
	}

	if request.Severity == "" {
		request.Severity = DefaultIncidentSeverity
	}

	if !isSupportedIncidentSeverity(
		request.Severity,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported incident severity",
			ErrInvalidIncidentRequest,
		)
	}

	if request.Priority == "" {
		request.Priority = DefaultIncidentPriority
	}

	if !isSupportedIncidentPriority(
		request.Priority,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported incident priority",
			ErrInvalidIncidentRequest,
		)
	}

	if !isSupportedIncidentDetectionSource(
		request.DetectionSource,
	) {
		return nil, fmt.Errorf(
			"%w: unsupported detection source",
			ErrInvalidIncidentRequest,
		)
	}

	departmentID, err := parseIncidentOptionalUUID(
		request.DepartmentID,
		"department ID",
	)
	if err != nil {
		return nil, err
	}

	affectedUserID, err := parseIncidentOptionalUUID(
		request.AffectedUserID,
		"affected user ID",
	)
	if err != nil {
		return nil, err
	}

	leadInvestigatorID, err :=
		parseIncidentOptionalUUID(
			request.LeadInvestigatorID,
			"lead investigator ID",
		)
	if err != nil {
		return nil, err
	}

	detectedAt, err := parseIncidentDetectedAt(
		request.DetectedAt,
	)
	if err != nil {
		return nil, err
	}

	reportedByPointer := incidentUUIDPointer(
		reportedBy,
	)

	err = s.repository.ValidateIncidentRelations(
		ctx,
		organizationID,
		departmentID,
		affectedUserID,
		leadInvestigatorID,
		reportedByPointer,
	)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	incidentID := uuid.New()
	status := DefaultIncidentStatus

	if leadInvestigatorID != nil {
		status = IncidentStatusAssigned
	}

	incident := &Incident{
		ID:             incidentID,
		OrganizationID: organizationID,
		DepartmentID:   departmentID,

		IncidentNumber: generateIncidentNumber(
			incidentID,
			now,
		),
		IncidentTitle: request.IncidentTitle,
		Description: normalizeIncidentOptionalText(
			request.Description,
		),
		IncidentCategory: request.IncidentCategory,
		Severity:         request.Severity,
		Priority:         request.Priority,
		Status:           status,
		DetectionSource:  request.DetectionSource,

		AffectedUserID: affectedUserID,
		AffectedDeviceName: normalizeIncidentOptionalText(
			request.AffectedDeviceName,
		),
		AffectedDeviceIdentifier: normalizeIncidentOptionalText(
			request.AffectedDeviceIdentifier,
		),
		LeadInvestigatorID: leadInvestigatorID,
		ReportedBy:         reportedByPointer,

		DataExposureSuspected: request.DataExposureSuspected,
		RansomwareSuspected:   request.RansomwareSuspected,
		DeviceIsolated:        request.DeviceIsolated,
		EvidencePreserved:     request.EvidencePreserved,

		AffectedRecordCount: request.AffectedRecordCount,
		EstimatedFinancialImpact: request.
			EstimatedFinancialImpact,

		InitialFindings: normalizeIncidentOptionalText(
			request.InitialFindings,
		),

		DetectedAt: detectedAt,
		ReportedAt: now,
	}

	err = s.repository.Create(
		ctx,
		incident,
		nil,
		reportedByPointer,
	)
	if err != nil {
		return nil, err
	}

	response := buildIncidentResponse(incident)

	return &response, nil
}

// GetIncident returns one organization incident.
func (s *IncidentService) GetIncident(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID string,
) (*IncidentResponse, error) {
	parsedIncidentID, err := parseIncidentRequiredUUID(
		incidentID,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	incident, err := s.repository.FindByID(
		ctx,
		organizationID,
		parsedIncidentID,
	)
	if err != nil {
		return nil, err
	}

	response := buildIncidentResponse(incident)

	return &response, nil
}

// ListIncidents returns validated, paginated organization incidents.
func (s *IncidentService) ListIncidents(
	ctx context.Context,
	organizationID uuid.UUID,
	request IncidentListQuery,
) (*IncidentListResponse, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	request.IncidentCategory = strings.ToUpper(
		strings.TrimSpace(request.IncidentCategory),
	)
	request.Severity = strings.ToUpper(
		strings.TrimSpace(request.Severity),
	)
	request.Priority = strings.ToUpper(
		strings.TrimSpace(request.Priority),
	)
	request.Status = strings.ToUpper(
		strings.TrimSpace(request.Status),
	)
	request.DetectionSource = strings.ToUpper(
		strings.TrimSpace(request.DetectionSource),
	)
	request.Search = strings.TrimSpace(
		request.Search,
	)

	if request.IncidentCategory != "" &&
		!isSupportedIncidentCategory(
			request.IncidentCategory,
		) {
		return nil, ErrInvalidIncidentRequest
	}

	if request.Severity != "" &&
		!isSupportedIncidentSeverity(
			request.Severity,
		) {
		return nil, ErrInvalidIncidentRequest
	}

	if request.Priority != "" &&
		!isSupportedIncidentPriority(
			request.Priority,
		) {
		return nil, ErrInvalidIncidentRequest
	}

	if request.Status != "" &&
		!isSupportedIncidentStatus(
			request.Status,
		) {
		return nil, ErrInvalidIncidentRequest
	}

	if request.DetectionSource != "" &&
		!isSupportedIncidentDetectionSource(
			request.DetectionSource,
		) {
		return nil, ErrInvalidIncidentRequest
	}

	departmentID, err := parseIncidentQueryUUID(
		request.DepartmentID,
		"department ID",
	)
	if err != nil {
		return nil, err
	}

	leadInvestigatorID, err :=
		parseIncidentQueryUUID(
			request.LeadInvestigatorID,
			"lead investigator ID",
		)
	if err != nil {
		return nil, err
	}

	from, err := parseIncidentFilterTime(
		request.From,
		"from",
	)
	if err != nil {
		return nil, err
	}

	to, err := parseIncidentFilterTime(
		request.To,
		"to",
	)
	if err != nil {
		return nil, err
	}

	if from != nil &&
		to != nil &&
		to.Before(*from) {
		return nil, fmt.Errorf(
			"%w: to must not be before from",
			ErrInvalidIncidentRequest,
		)
	}

	page := request.Page
	if page <= 0 {
		page = 1
	}

	pageSize := request.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}

	if pageSize > 100 {
		pageSize = 100
	}

	incidents, total, err := s.repository.List(
		ctx,
		IncidentFilter{
			OrganizationID:     organizationID,
			DepartmentID:       departmentID,
			IncidentCategory:   request.IncidentCategory,
			Severity:           request.Severity,
			Priority:           request.Priority,
			Status:             request.Status,
			DetectionSource:    request.DetectionSource,
			LeadInvestigatorID: leadInvestigatorID,
			Search:             request.Search,
			From:               from,
			To:                 to,
			Limit:              pageSize,
			Offset:             (page - 1) * pageSize,
		},
	)
	if err != nil {
		return nil, err
	}

	items := make(
		[]IncidentResponse,
		0,
		len(incidents),
	)

	for index := range incidents {
		items = append(
			items,
			buildIncidentResponse(
				&incidents[index],
			),
		)
	}

	totalPages := 0

	if total > 0 {
		totalPages = int(
			(total + int64(pageSize) - 1) /
				int64(pageSize),
		)
	}

	return &IncidentListResponse{
		Incidents:  items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func buildIncidentResponse(
	incident *Incident,
) IncidentResponse {
	return IncidentResponse{
		ID: incident.ID.String(),
		OrganizationID: incident.OrganizationID.
			String(),
		DepartmentID: incidentOptionalUUIDString(
			incident.DepartmentID,
		),

		IncidentNumber:   incident.IncidentNumber,
		IncidentTitle:    incident.IncidentTitle,
		Description:      incident.Description,
		IncidentCategory: incident.IncidentCategory,
		Severity:         incident.Severity,
		Priority:         incident.Priority,
		Status:           incident.Status,
		DetectionSource:  incident.DetectionSource,

		AffectedUserID: incidentOptionalUUIDString(
			incident.AffectedUserID,
		),
		AffectedDeviceName: incident.
			AffectedDeviceName,
		AffectedDeviceIdentifier: incident.
			AffectedDeviceIdentifier,
		LeadInvestigatorID: incidentOptionalUUIDString(
			incident.LeadInvestigatorID,
		),
		ReportedBy: incidentOptionalUUIDString(
			incident.ReportedBy,
		),

		DataExposureSuspected: incident.
			DataExposureSuspected,
		RansomwareSuspected: incident.
			RansomwareSuspected,
		DeviceIsolated:    incident.DeviceIsolated,
		EvidencePreserved: incident.EvidencePreserved,

		AffectedRecordCount: incident.
			AffectedRecordCount,
		EstimatedFinancialImpact: incident.
			EstimatedFinancialImpact,

		InitialFindings: incident.InitialFindings,
		RootCause:       incident.RootCause,
		ContainmentSummary: incident.
			ContainmentSummary,
		ResolutionSummary: incident.
			ResolutionSummary,

		DetectedAt: incident.DetectedAt,
		ReportedAt: incident.ReportedAt,
		InvestigationStartedAt: incident.
			InvestigationStartedAt,
		ContainedAt: incident.ContainedAt,
		ResolvedAt:  incident.ResolvedAt,
		ClosedAt:    incident.ClosedAt,
		CreatedAt:   incident.CreatedAt,
		UpdatedAt:   incident.UpdatedAt,
	}
}

func generateIncidentNumber(
	incidentID uuid.UUID,
	createdAt time.Time,
) string {
	identifier := strings.ReplaceAll(
		incidentID.String(),
		"-",
		"",
	)

	return fmt.Sprintf(
		"%s-%s-%s",
		IncidentNumberPrefix,
		createdAt.UTC().Format("20060102"),
		strings.ToUpper(identifier[:8]),
	)
}

func parseIncidentRequiredUUID(
	value string,
	fieldName string,
) (uuid.UUID, error) {
	parsedValue, err := uuid.Parse(
		strings.TrimSpace(value),
	)
	if err != nil ||
		parsedValue == uuid.Nil {
		return uuid.Nil, fmt.Errorf(
			"%w: %s must be a valid UUID",
			ErrInvalidIncidentRequest,
			fieldName,
		)
	}

	return parsedValue, nil
}

func parseIncidentOptionalUUID(
	value *string,
	fieldName string,
) (*uuid.UUID, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return nil, nil
	}

	parsedValue, err := parseIncidentRequiredUUID(
		*value,
		fieldName,
	)
	if err != nil {
		return nil, err
	}

	return &parsedValue, nil
}

func parseIncidentQueryUUID(
	value string,
	fieldName string,
) (*uuid.UUID, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	parsedValue, err := parseIncidentRequiredUUID(
		value,
		fieldName,
	)
	if err != nil {
		return nil, err
	}

	return &parsedValue, nil
}

func parseIncidentDetectedAt(
	value *string,
) (time.Time, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return time.Now().UTC(), nil
	}

	parsedValue, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(*value),
	)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"%w: detected_at must use RFC3339 format",
			ErrInvalidIncidentRequest,
		)
	}

	parsedValue = parsedValue.UTC()

	if parsedValue.After(
		time.Now().UTC().Add(5 * time.Minute),
	) {
		return time.Time{},
			ErrIncidentFutureDetectionTime
	}

	return parsedValue, nil
}

func parseIncidentFilterTime(
	value string,
	fieldName string,
) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	parsedValue, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(value),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %s must use RFC3339 format",
			ErrInvalidIncidentRequest,
			fieldName,
		)
	}

	parsedValue = parsedValue.UTC()

	return &parsedValue, nil
}

func normalizeIncidentOptionalText(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	trimmedValue := strings.TrimSpace(*value)
	if trimmedValue == "" {
		return nil
	}

	return &trimmedValue
}

func incidentOptionalUUIDString(
	value *uuid.UUID,
) *string {
	if value == nil {
		return nil
	}

	stringValue := value.String()

	return &stringValue
}

func isSupportedIncidentCategory(
	value string,
) bool {
	switch value {
	case IncidentCategoryUnauthorizedAccess,
		IncidentCategoryHoneytokenTrigger,
		IncidentCategoryCanaryFileTrigger,
		IncidentCategoryRansomware,
		IncidentCategoryMalware,
		IncidentCategoryPhishing,
		IncidentCategoryDataBreach,
		IncidentCategoryInsiderThreat,
		IncidentCategoryAccountCompromise,
		IncidentCategoryAPIAttack,
		IncidentCategoryDeepfake,
		IncidentCategoryDigitalEvidence,
		IncidentCategoryPolicyViolation,
		IncidentCategorySystemAnomaly,
		IncidentCategoryOther:
		return true

	default:
		return false
	}
}

func isSupportedIncidentSeverity(
	value string,
) bool {
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

func isSupportedIncidentPriority(
	value string,
) bool {
	switch value {
	case IncidentPriorityLow,
		IncidentPriorityMedium,
		IncidentPriorityHigh,
		IncidentPriorityUrgent:
		return true

	default:
		return false
	}
}

func isSupportedIncidentDetectionSource(
	value string,
) bool {
	switch value {
	case IncidentDetectionSourceSecurityAlert,
		IncidentDetectionSourceHoneytoken,
		IncidentDetectionSourceCanaryFile,
		IncidentDetectionSourceFileMonitoring,
		IncidentDetectionSourceAIAnalysis,
		IncidentDetectionSourceUserReport,
		IncidentDetectionSourceAdminReport,
		IncidentDetectionSourceSystem,
		IncidentDetectionSourceExternalReport,
		IncidentDetectionSourceOther:
		return true

	default:
		return false
	}
}

func isSupportedIncidentStatus(
	value string,
) bool {
	switch value {
	case IncidentStatusOpen,
		IncidentStatusAssigned,
		IncidentStatusInvestigating,
		IncidentStatusContained,
		IncidentStatusEradicated,
		IncidentStatusRecovering,
		IncidentStatusResolved,
		IncidentStatusClosed,
		IncidentStatusReopened,
		IncidentStatusCancelled:
		return true

	default:
		return false
	}
}
