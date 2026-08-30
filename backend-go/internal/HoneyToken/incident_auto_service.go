package honeytoken

import (
	"context"
	"encoding/json"
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

	// Preserve the triggering endpoint event as immutable incident evidence.
	// This deliberately stores only forensic metadata and existing hashes; it
	// never copies raw file content, paths, command lines, or watcher payloads.
	// A vault object can be attached later by a privileged evidence workflow.
	evidencePreserved := s.preserveTriggeringFileEvent(ctx, incident, threat)
	if evidencePreserved {
		incident.EvidencePreserved = true
	}

	response := buildIncidentResponse(incident)
	reason = "eligible threat escalated to incident"
	if evidencePreserved {
		reason += " and triggering event evidence was preserved"
	} else {
		reason += "; triggering event evidence requires follow-up"
	}

	return &IncidentAutomationResult{
		IncidentCreated: true,
		Incident:        &response,
		Reason:          reason,
	}, nil
}

// preserveTriggeringFileEvent adds an immutable metadata-only evidence record
// for the file event that produced an automated incident. Failure is not
// allowed to undo a successfully created critical incident; callers can use
// the incident's EvidencePreserved flag to identify required follow-up.
func (s *IncidentAutomationService) preserveTriggeringFileEvent(
	ctx context.Context,
	incident *Incident,
	threat *Threat,
) bool {
	if s == nil || s.repository == nil || s.repository.db == nil ||
		incident == nil || threat == nil || threat.PrimaryFileEventID == nil ||
		*threat.PrimaryFileEventID == uuid.Nil {
		return false
	}

	var event struct {
		ID              uuid.UUID
		EventCode       string
		EventType       string
		EventSource     string
		DetectionMethod string
		FileName        string
		MimeType        *string
		FileSizeAfter   *int64
		CurrentHash     *string
		EvidenceHash    *string
		HashAlgorithm   string
		OccurredAt      time.Time
	}
	err := s.repository.db.QueryRow(ctx, `
		SELECT id, event_code, event_type, event_source, detection_method,
		       file_name, mime_type, file_size_after, current_hash,
		       evidence_hash, hash_algorithm, occurred_at
		FROM file_events
		WHERE id = $1 AND organization_id = $2`,
		*threat.PrimaryFileEventID, incident.OrganizationID,
	).Scan(
		&event.ID, &event.EventCode, &event.EventType, &event.EventSource,
		&event.DetectionMethod, &event.FileName, &event.MimeType,
		&event.FileSizeAfter, &event.CurrentHash, &event.EvidenceHash,
		&event.HashAlgorithm, &event.OccurredAt,
	)
	if err != nil {
		return false
	}

	hash := event.EvidenceHash
	if hash == nil || strings.TrimSpace(*hash) == "" {
		hash = event.CurrentHash
	}
	hashAlgorithm := strings.ToUpper(strings.TrimSpace(event.HashAlgorithm))
	integrityStatus := IncidentEvidenceIntegrityUnavailable
	if hashAlgorithm == IncidentEvidenceHashAlgorithmSHA256 &&
		hash != nil && len(strings.TrimSpace(*hash)) == 64 {
		normalized := strings.ToLower(strings.TrimSpace(*hash))
		hash = &normalized
		integrityStatus = IncidentEvidenceIntegrityPending
	} else {
		hash = nil
		hashAlgorithm = IncidentEvidenceHashAlgorithmSHA256
	}

	metadata, err := json.Marshal(map[string]any{
		"automation":           "incident-triggering-file-event",
		"event_code":           event.EventCode,
		"event_type":           event.EventType,
		"event_source":         event.EventSource,
		"detection_method":     event.DetectionMethod,
		"content_preserved":    false,
		"vault_link_status":    "METADATA_ONLY",
		"raw_content_excluded": true,
	})
	if err != nil {
		return false
	}
	description := "Automatically preserved metadata for the endpoint event that triggered this incident. Raw content and paths are excluded."
	evidenceID := uuid.New()
	evidence := &IncidentEvidence{
		ID:              evidenceID,
		IncidentID:      incident.ID,
		OrganizationID:  incident.OrganizationID,
		EvidenceCode:    generateIncidentEvidenceCode(evidenceID, time.Now().UTC()),
		EvidenceType:    IncidentEvidenceTypeFileEvent,
		EvidenceName:    "Triggering file event: " + event.FileName,
		Description:     &description,
		ThreatID:        &threat.ID,
		FileEventID:     &event.ID,
		ProtectedFileID: threat.ProtectedFileID,
		HoneytokenID:    threat.HoneytokenID,
		CanaryFileID:    threat.CanaryFileID,
		MimeType:        event.MimeType,
		FileSizeBytes:   event.FileSizeAfter,
		EvidenceHash:    hash,
		HashAlgorithm:   hashAlgorithm,
		IntegrityStatus: integrityStatus,
		IsImmutable:     true,
		CollectedAt:     event.OccurredAt.UTC(),
		Metadata:        metadata,
	}
	// The automated service is not a user; the repository records a system
	// timeline event with no impersonated actor.
	return s.repository.CreateEvidence(ctx, evidence, uuid.Nil) == nil
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
