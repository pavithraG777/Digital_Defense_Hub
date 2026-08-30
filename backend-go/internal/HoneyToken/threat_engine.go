package honeytoken

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultThreatCorrelationWindow = 10 * time.Minute
	minimumThreatCreationScore     = 40
)

// ThreatSignal is the normalized security signal received from the file-event
// monitoring layer.
type ThreatSignal struct {
	FileEventID       uuid.UUID
	OrganizationID    uuid.UUID
	DepartmentID      *uuid.UUID
	MonitoringRuleID  *uuid.UUID
	ProtectedFileID   *uuid.UUID
	HoneytokenID      *uuid.UUID
	CanaryFileID      *uuid.UUID
	ResourceType      string
	EventType         string
	DetectionMethod   string
	OccurredAt        time.Time
	PreliminaryScore  int
	Suspicious        bool
	AffectedFileCount int
	ProcessName       *string
	ProcessID         *int64
	ProcessPath       *string
	DeviceName        *string
	DeviceIdentifier  *string
	SourceIPAddress   *string
	OriginalPath      *string
	CurrentPath       *string
	PreviousHash      *string
	CurrentHash       *string
	EvidenceLocation  *string
	Metadata          json.RawMessage
}

// ThreatEngine performs rule-based threat scoring and correlation.
type ThreatEngine struct {
	repository        *ThreatRepository
	correlationWindow time.Duration
}

type threatAssessment struct {
	ThreatType         string
	Category           string
	Title              string
	Description        string
	Severity           string
	Score              int
	Confidence         float64
	Classification     string
	Indicators         json.RawMessage
	RiskFactors        json.RawMessage
	EvidenceSummary    json.RawMessage
	RecommendedActions json.RawMessage
}

func NewThreatEngine(
	repository *ThreatRepository,
) (*ThreatEngine, error) {
	if repository == nil {
		return nil, errors.New("threat repository is required")
	}

	return &ThreatEngine{
		repository:        repository,
		correlationWindow: defaultThreatCorrelationWindow,
	}, nil
}

// Analyze evaluates a normalized file-event signal and either creates a new
// threat, correlates it with an existing threat, or safely ignores it.
func (e *ThreatEngine) Analyze(
	ctx context.Context,
	signal ThreatSignal,
) (*ThreatDetectionResult, error) {
	if err := validateThreatSignal(signal); err != nil {
		return nil, err
	}

	if signal.OccurredAt.IsZero() {
		signal.OccurredAt = time.Now().UTC()
	}

	if signal.AffectedFileCount < 1 {
		signal.AffectedFileCount = 1
	}

	if strings.TrimSpace(signal.DetectionMethod) == "" {
		signal.DetectionMethod = "RULE_BASED"
	}

	assessment, err := assessThreatSignal(signal)
	if err != nil {
		return nil, err
	}

	if assessment.Score < minimumThreatCreationScore {
		return &ThreatDetectionResult{
			ThreatCreated: false,
			Reason: fmt.Sprintf(
				"signal score %d is below threat threshold %d",
				assessment.Score,
				minimumThreatCreationScore,
			),
		}, nil
	}

	correlationKey := buildThreatCorrelationKey(
		signal,
		assessment.ThreatType,
		e.correlationWindow,
	)

	existingThreat, err := e.repository.FindByCorrelationKey(
		ctx,
		signal.OrganizationID,
		correlationKey,
	)
	if err == nil {
		return e.correlateExistingThreat(
			ctx,
			existingThreat,
			signal,
			assessment,
		)
	}

	if !errors.Is(err, ErrThreatNotFound) {
		return nil, fmt.Errorf(
			"find correlated threat: %w",
			err,
		)
	}

	threatID := uuid.New()
	description := assessment.Description

	threat := &Threat{
		ID:                 threatID,
		ThreatCode:         generateThreatCode(threatID, signal.OccurredAt),
		CorrelationKey:     &correlationKey,
		OrganizationID:     signal.OrganizationID,
		DepartmentID:       signal.DepartmentID,
		PrimaryFileEventID: &signal.FileEventID,
		MonitoringRuleID:   signal.MonitoringRuleID,
		ProtectedFileID:    signal.ProtectedFileID,
		HoneytokenID:       signal.HoneytokenID,
		CanaryFileID:       signal.CanaryFileID,
		ThreatType:         assessment.ThreatType,
		ThreatCategory:     assessment.Category,
		DetectionMethod: strings.ToUpper(
			strings.TrimSpace(signal.DetectionMethod),
		),
		Title:              assessment.Title,
		Description:        &description,
		Severity:           assessment.Severity,
		ThreatScore:        assessment.Score,
		ConfidenceScore:    assessment.Confidence,
		Classification:     assessment.Classification,
		Status:             ThreatStatusDetected,
		EventCount:         1,
		AffectedFileCount:  signal.AffectedFileCount,
		FirstDetectedAt:    signal.OccurredAt,
		LastDetectedAt:     signal.OccurredAt,
		ProcessName:        signal.ProcessName,
		ProcessID:          signal.ProcessID,
		ProcessPath:        signal.ProcessPath,
		DeviceName:         signal.DeviceName,
		DeviceIdentifier:   signal.DeviceIdentifier,
		SourceIPAddress:    signal.SourceIPAddress,
		Indicators:         assessment.Indicators,
		RiskFactors:        assessment.RiskFactors,
		EvidenceSummary:    assessment.EvidenceSummary,
		RecommendedActions: assessment.RecommendedActions,
		ContainmentActions: json.RawMessage(`[]`),
	}

	if err = e.repository.Create(ctx, threat); err != nil {
		return nil, fmt.Errorf("create detected threat: %w", err)
	}

	response := threatToResponse(threat)
	response.FileEvents = []ThreatFileEventResponse{
		{
			FileEventID:  signal.FileEventID.String(),
			RelationType: ThreatEventRelationPrimary,
			CreatedAt:    threat.CreatedAt,
		},
	}

	return &ThreatDetectionResult{
		ThreatCreated: true,
		Threat:        &response,
		Reason:        "new security threat detected",
	}, nil
}

func (e *ThreatEngine) correlateExistingThreat(
	ctx context.Context,
	existing *Threat,
	signal ThreatSignal,
	assessment threatAssessment,
) (*ThreatDetectionResult, error) {
	combinedScore := assessment.Score
	if existing.ThreatScore > combinedScore {
		combinedScore = existing.ThreatScore
	}

	eventBoost := existing.EventCount * 3
	if eventBoost > 15 {
		eventBoost = 15
	}

	combinedScore = clampThreatScore(
		combinedScore + eventBoost,
	)

	severity := calculateThreatSeverity(combinedScore)
	classification := calculateThreatClassification(combinedScore)

	confidence := assessment.Confidence
	if existing.ConfidenceScore > confidence {
		confidence = existing.ConfidenceScore
	}

	confidence += float64(eventBoost) / 2
	if confidence > 99 {
		confidence = 99
	}

	// occurrence_count is the number of correlated accesses.  Do not inflate
	// affected_file_count when the same protected/canary/honeytoken resource is
	// touched again; one file accessed five times is still one affected file.
	affectedFileCount := existing.AffectedFileCount
	if !isSameThreatResource(existing, signal) {
		affectedFileCount += signal.AffectedFileCount
	}

	correlated, err := e.repository.CorrelateFileEvent(
		ctx,
		signal.OrganizationID,
		existing.ID,
		signal.FileEventID,
		ThreatEventRelationCorrelated,
		ThreatCorrelationUpdate{
			OccurredAt:        signal.OccurredAt,
			Severity:          severity,
			ThreatScore:       combinedScore,
			ConfidenceScore:   confidence,
			Classification:    classification,
			AffectedFileCount: affectedFileCount,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"correlate threat file event: %w",
			err,
		)
	}

	if !correlated {
		response := threatToResponse(existing)

		return &ThreatDetectionResult{
			ThreatCreated: false,
			Threat:        &response,
			Reason:        "file event was already correlated",
		}, nil
	}

	updatedThreat, err := e.repository.FindByID(
		ctx,
		signal.OrganizationID,
		existing.ID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"reload correlated threat: %w",
			err,
		)
	}

	response := threatToResponse(updatedThreat)

	return &ThreatDetectionResult{
		ThreatCreated: false,
		Threat:        &response,
		Reason:        "file event correlated with existing threat",
	}, nil
}

func isSameThreatResource(existing *Threat, signal ThreatSignal) bool {
	if existing == nil {
		return false
	}
	return sameThreatUUID(existing.HoneytokenID, signal.HoneytokenID) ||
		sameThreatUUID(existing.CanaryFileID, signal.CanaryFileID) ||
		sameThreatUUID(existing.ProtectedFileID, signal.ProtectedFileID)
}

func sameThreatUUID(left, right *uuid.UUID) bool {
	return left != nil && right != nil && *left != uuid.Nil && *left == *right
}

func validateThreatSignal(signal ThreatSignal) error {
	if signal.FileEventID == uuid.Nil {
		return fmt.Errorf(
			"%w: file_event_id is required",
			ErrInvalidThreatRequest,
		)
	}

	if signal.OrganizationID == uuid.Nil {
		return fmt.Errorf(
			"%w: organization_id is required",
			ErrInvalidThreatRequest,
		)
	}

	if strings.TrimSpace(signal.EventType) == "" {
		return fmt.Errorf(
			"%w: event_type is required",
			ErrInvalidThreatRequest,
		)
	}

	return nil
}

func assessThreatSignal(
	signal ThreatSignal,
) (threatAssessment, error) {
	eventType := strings.ToUpper(
		strings.TrimSpace(signal.EventType),
	)
	resourceType := strings.ToUpper(
		strings.TrimSpace(signal.ResourceType),
	)

	score := baseThreatEventScore(eventType)

	if signal.PreliminaryScore > score {
		score = signal.PreliminaryScore
	}

	if signal.Suspicious {
		score += 15
	}

	if signal.PreviousHash != nil &&
		signal.CurrentHash != nil &&
		*signal.PreviousHash != "" &&
		*signal.CurrentHash != "" &&
		*signal.PreviousHash != *signal.CurrentHash {
		score += 20
	}

	// A deception interaction is strong evidence that a resource was touched,
	// but it is not proof of compromise by itself.  Previously a canary or
	// honeytoken event was forced to 85/95 (and an encrypted event to 100),
	// making the score indistinguishable from a corroborated attack.  Use a
	// calibrated signal instead; recurrence and independent evidence still
	// raise the correlated score later in the workflow.
	switch resourceType {
	case "HONEYTOKEN":
		score = calibratedDeceptionScore(signal, eventType, 55, 78)
	case "CANARY_FILE":
		score = calibratedDeceptionScore(signal, eventType, 45, 72)
	case "PROTECTED_FILE":
		score += 10
	}

	score = clampThreatScore(score)

	threatType, category, title := classifyThreatBehaviour(
		resourceType,
		eventType,
	)

	description := fmt.Sprintf(
		"%s event detected on %s resource",
		eventType,
		normalizeThreatResourceName(resourceType),
	)

	riskFactors := buildThreatRiskFactors(
		signal,
		resourceType,
		eventType,
	)

	indicators, err := json.Marshal(map[string]any{
		"event_type":        eventType,
		"resource_type":     resourceType,
		"suspicious":        signal.Suspicious,
		"preliminary_score": signal.PreliminaryScore,
		"process_name":      signal.ProcessName,
		"process_path":      signal.ProcessPath,
		"device_identifier": signal.DeviceIdentifier,
		"original_path":     signal.OriginalPath,
		"current_path":      signal.CurrentPath,
		"previous_hash":     signal.PreviousHash,
		"current_hash":      signal.CurrentHash,
	})
	if err != nil {
		return threatAssessment{}, fmt.Errorf(
			"marshal threat indicators: %w",
			err,
		)
	}

	evidenceSummary, err := json.Marshal(map[string]any{
		"file_event_id":     signal.FileEventID.String(),
		"occurred_at":       signal.OccurredAt,
		"evidence_location": signal.EvidenceLocation,
		"metadata":          signal.Metadata,
	})
	if err != nil {
		return threatAssessment{}, fmt.Errorf(
			"marshal threat evidence summary: %w",
			err,
		)
	}

	recommendedActions, err := json.Marshal(
		recommendedThreatActions(threatType, score),
	)
	if err != nil {
		return threatAssessment{}, fmt.Errorf(
			"marshal recommended threat actions: %w",
			err,
		)
	}

	riskFactorsJSON, err := json.Marshal(riskFactors)
	if err != nil {
		return threatAssessment{}, fmt.Errorf(
			"marshal threat risk factors: %w",
			err,
		)
	}

	return threatAssessment{
		ThreatType:         threatType,
		Category:           category,
		Title:              title,
		Description:        description,
		Severity:           calculateThreatSeverity(score),
		Score:              score,
		Confidence:         calculateThreatConfidence(score, resourceType),
		Classification:     calculateThreatClassification(score),
		Indicators:         indicators,
		RiskFactors:        riskFactorsJSON,
		EvidenceSummary:    evidenceSummary,
		RecommendedActions: recommendedActions,
	}, nil
}

func calibratedDeceptionScore(signal ThreatSignal, eventType string, floor int, encryptedScore int) int {
	score := deceptionThreatEventScore(eventType, floor, encryptedScore)
	if signal.Suspicious {
		score += 8
	}
	if signal.PreviousHash != nil && signal.CurrentHash != nil &&
		*signal.PreviousHash != "" && *signal.CurrentHash != "" &&
		*signal.PreviousHash != *signal.CurrentHash {
		score += 10
	}
	if signal.PreliminaryScore > score {
		// Upstream tools may supply a higher evidence-backed score, but a
		// single deception event never claims perfect certainty.
		score = min(signal.PreliminaryScore, 95)
	}
	return score
}

// deceptionThreatEventScore prevents a high-risk generic file event from
// automatically becoming a 100/100 threat merely because the file is a
// canary. The caller has already applied suspicious/hash evidence before
// this function, so keep the bare deception signal at its calibrated floor.
func deceptionThreatEventScore(eventType string, floor int, encryptedScore int) int {
	switch eventType {
	case "ENCRYPTED", "MULTIPLE_FILE_CHANGES":
		return encryptedScore
	case "DELETED", "HASH_CHANGED", "PERMISSION_CHANGED":
		return floor + 15
	case "MODIFIED", "RENAMED", "MOVED":
		return floor + 8
	default:
		return floor
	}
}

func baseThreatEventScore(eventType string) int {
	switch eventType {
	case "ENCRYPTED":
		return 100
	case "MULTIPLE_FILE_CHANGES":
		return 95
	case "HASH_CHANGED":
		return 80
	case "DELETED":
		return 70
	case "PERMISSION_CHANGED":
		return 65
	case "RENAMED":
		return 60
	case "MOVED":
		return 55
	case "MODIFIED":
		return 50
	case "COPIED":
		return 40
	case "CREATED":
		return 35
	case "OPENED", "READ":
		return 25
	default:
		return 20
	}
}

func classifyThreatBehaviour(
	resourceType string,
	eventType string,
) (string, string, string) {
	if resourceType == "HONEYTOKEN" {
		return ThreatTypeHoneytokenAccess,
			ThreatCategoryDeception,
			"Honeytoken interaction detected"
	}

	if resourceType == "CANARY_FILE" {
		return ThreatTypeCanaryTriggered,
			ThreatCategoryDeception,
			"Canary file triggered"
	}

	switch eventType {
	case "ENCRYPTED", "MULTIPLE_FILE_CHANGES":
		return ThreatTypeRansomwareActivity,
			ThreatCategoryRansomware,
			"Potential ransomware activity detected"

	case "HASH_CHANGED":
		return ThreatTypeHashMismatch,
			ThreatCategoryIntegrity,
			"Protected file integrity mismatch detected"

	case "PERMISSION_CHANGED":
		return ThreatTypePermissionAbuse,
			ThreatCategoryAccessControl,
			"Suspicious file permission change detected"

	case "MODIFIED", "RENAMED", "MOVED", "DELETED":
		return ThreatTypeFileTampering,
			ThreatCategoryIntegrity,
			"File tampering activity detected"

	default:
		return ThreatTypeCustom,
			ThreatCategoryBehaviourAnomaly,
			"Suspicious file-system behaviour detected"
	}
}

func buildThreatRiskFactors(
	signal ThreatSignal,
	resourceType string,
	eventType string,
) []string {
	riskFactors := make([]string, 0)

	if signal.Suspicious {
		riskFactors = append(
			riskFactors,
			"FILE_EVENT_MARKED_SUSPICIOUS",
		)
	}

	if resourceType == "HONEYTOKEN" {
		riskFactors = append(
			riskFactors,
			"HONEYTOKEN_INTERACTION",
		)
	}

	if resourceType == "CANARY_FILE" {
		riskFactors = append(
			riskFactors,
			"CANARY_FILE_INTERACTION",
		)
	}

	if eventType == "ENCRYPTED" {
		riskFactors = append(
			riskFactors,
			"UNAUTHORIZED_ENCRYPTION_BEHAVIOUR",
		)
	}

	if eventType == "MULTIPLE_FILE_CHANGES" {
		riskFactors = append(
			riskFactors,
			"HIGH_VOLUME_FILE_ACTIVITY",
		)
	}

	if signal.PreviousHash != nil &&
		signal.CurrentHash != nil &&
		*signal.PreviousHash != *signal.CurrentHash {
		riskFactors = append(
			riskFactors,
			"FILE_HASH_CHANGED",
		)
	}

	if signal.ProcessName != nil ||
		signal.ProcessPath != nil {
		riskFactors = append(
			riskFactors,
			"PROCESS_INFORMATION_AVAILABLE",
		)
	}

	if len(riskFactors) == 0 {
		riskFactors = append(
			riskFactors,
			"RULE_BASED_FILE_EVENT_MATCH",
		)
	}

	return riskFactors
}

func recommendedThreatActions(
	threatType string,
	score int,
) []string {
	actions := []string{
		"Review the correlated file event and process information",
		"Preserve available file-system evidence",
		"Verify the affected file hash and access history",
	}

	if score >= 70 {
		actions = append(
			actions,
			"Temporarily restrict write access to the affected location",
			"Inspect other recent events from the same device and process",
		)
	}

	if score >= 90 ||
		threatType == ThreatTypeRansomwareActivity {
		actions = append(
			actions,
			"Isolate the affected process or endpoint after authorization",
			"Escalate the threat for immediate incident creation",
		)
	}

	return actions
}

func calculateThreatSeverity(score int) string {
	switch {
	case score >= 90:
		return ThreatLevelCritical
	case score >= 70:
		return ThreatLevelHigh
	case score >= 40:
		return ThreatLevelMedium
	default:
		return ThreatLevelLow
	}
}

func calculateThreatClassification(score int) string {
	switch {
	case score >= 90:
		return ThreatClassificationMalicious
	case score >= 75:
		return ThreatClassificationLikelyMalicious
	case score >= 40:
		return ThreatClassificationSuspicious
	default:
		return ThreatClassificationUnknown
	}
}

func calculateThreatConfidence(
	score int,
	resourceType string,
) float64 {
	if resourceType == "HONEYTOKEN" ||
		resourceType == "CANARY_FILE" {
		return 98
	}

	confidence := 50 + (float64(score) * 0.45)
	if confidence > 95 {
		return 95
	}

	return confidence
}

func buildThreatCorrelationKey(
	signal ThreatSignal,
	threatType string,
	window time.Duration,
) string {
	occurredAt := signal.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	windowNumber := occurredAt.Unix() /
		int64(window.Seconds())

	device := threatOptionalString(signal.DeviceIdentifier)
	if device == "" {
		device = threatOptionalString(signal.DeviceName)
	}

	process := threatOptionalString(signal.ProcessPath)
	if process == "" {
		process = threatOptionalString(signal.ProcessName)
	}

	resource := threatSignalResourceIdentifier(signal)

	if threatType == ThreatTypeRansomwareActivity ||
		threatType == ThreatTypeMassFileModification ||
		threatType == ThreatTypeMassFileRename ||
		threatType == ThreatTypeMassFileDeletion {
		resource = ""
	}

	rawKey := fmt.Sprintf(
		"%s|%s|%s|%s|%s|%d",
		signal.OrganizationID.String(),
		threatType,
		device,
		process,
		resource,
		windowNumber,
	)

	digest := sha256.Sum256([]byte(rawKey))

	return hex.EncodeToString(digest[:])
}

func threatSignalResourceIdentifier(signal ThreatSignal) string {
	switch {
	case signal.HoneytokenID != nil:
		return signal.HoneytokenID.String()
	case signal.CanaryFileID != nil:
		return signal.CanaryFileID.String()
	case signal.ProtectedFileID != nil:
		return signal.ProtectedFileID.String()
	default:
		return threatOptionalString(signal.CurrentPath)
	}
}

func generateThreatCode(
	threatID uuid.UUID,
	occurredAt time.Time,
) string {
	identifier := strings.ToUpper(
		strings.ReplaceAll(threatID.String(), "-", ""),
	)

	return fmt.Sprintf(
		"DDH-THR-%s-%s",
		occurredAt.UTC().Format("20060102"),
		identifier[:8],
	)
}

func clampThreatScore(score int) int {
	switch {
	case score < 0:
		return 0
	case score > 100:
		return 100
	default:
		return score
	}
}

func normalizeThreatResourceName(resourceType string) string {
	if strings.TrimSpace(resourceType) == "" {
		return "UNKNOWN"
	}

	return resourceType
}

func threatOptionalString(value *string) string {
	if value == nil {
		return ""
	}

	return strings.TrimSpace(*value)
}
