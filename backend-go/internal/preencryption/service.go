package preencryption

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultDetectionWindow = 60 * time.Second

	maximumDetectionWindow = 15 * time.Minute

	defaultMinimumDetectionScore = 25.0
)

type storedRiskFactorPayload struct {
	SchemaVersion string `json:"schema_version"`

	DetectionMethod string `json:"detection_method"`

	RuleScore float64  `json:"rule_score"`
	AIScore   *float64 `json:"ai_score,omitempty"`

	ModelName     *string `json:"model_name,omitempty"`
	ModelVersion  *string `json:"model_version,omitempty"`
	PolicyVersion *string `json:"policy_version,omitempty"`

	RuleFactors []RiskFactor `json:"rule_factors"`
	AIFactors   []RiskFactor `json:"ai_factors,omitempty"`
}

type detectionMetadataPayload struct {
	TriggerFileEventID uuid.UUID `json:"trigger_file_event_id"`

	FeatureSchemaVersion string `json:"feature_schema_version"`

	WindowFingerprint string `json:"window_fingerprint"`

	EngineStatus string `json:"engine_status"`

	EventCount int `json:"event_count"`
}

// AnalysisResult describes the outcome of processing
// one file event through the pre-encryption engine.
type AnalysisResult struct {
	Detection *Detection `json:"detection,omitempty"`

	Created bool `json:"created"`
	Skipped bool `json:"skipped"`

	SkippedReason string `json:"skipped_reason,omitempty"`

	EngineFallback bool `json:"engine_fallback"`

	EngineError error `json:"-"`
}

type Service struct {
	repository *Repository
	engine     *EngineClient

	featurePolicy FeaturePolicy

	windowDuration time.Duration

	minimumDetectionScore float64
}

func NewService(
	repository *Repository,
	engine *EngineClient,
	featurePolicy FeaturePolicy,
	windowDuration time.Duration,
	minimumDetectionScore float64,
) (*Service, error) {
	if repository == nil {
		return nil, errors.New(
			"pre-encryption repository is required",
		)
	}

	if windowDuration <= 0 {
		windowDuration =
			defaultDetectionWindow
	}

	if windowDuration >
		maximumDetectionWindow {
		return nil, errors.New(
			"pre-encryption detection window exceeds maximum duration",
		)
	}

	if !IsValidScore(
		minimumDetectionScore,
	) ||
		minimumDetectionScore == 0 {
		minimumDetectionScore =
			defaultMinimumDetectionScore
	}

	return &Service{
		repository: repository,
		engine:     engine,

		featurePolicy: normalizeFeaturePolicy(
			featurePolicy,
		),

		windowDuration: windowDuration,

		minimumDetectionScore: minimumDetectionScore,
	}, nil
}

func (s *Service) AnalyzeFileEvent(
	ctx context.Context,
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
) (*AnalysisResult, error) {
	if s == nil ||
		s.repository == nil {
		return nil, errors.New(
			"pre-encryption service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if fileEventID == uuid.Nil {
		return nil, errors.New(
			"file event ID is required",
		)
	}

	triggerEvent, err :=
		s.repository.
			GetFileEventObservation(
				ctx,
				organizationID,
				fileEventID,
			)
	if err != nil {
		return nil, err
	}

	if !IsPreEncryptionRelevantEventType(
		triggerEvent.EventType,
	) {
		return &AnalysisResult{
			Skipped:       true,
			SkippedReason: "file event type is not relevant",
		}, nil
	}

	windowEndedAt :=
		triggerEvent.OccurredAt.UTC()

	windowStartedAt :=
		windowEndedAt.Add(
			-s.windowDuration,
		)

	fallbackFilePath :=
		strings.TrimSpace(
			triggerEvent.FilePath,
		)

	events, err :=
		s.repository.
			ListRelatedFileEvents(
				ctx,
				organizationID,
				triggerEvent.DeviceIdentifier,
				triggerEvent.ProcessID,
				&fallbackFilePath,
				windowStartedAt,
				windowEndedAt,
				maximumRelatedEventLimit,
			)
	if err != nil {
		return nil, err
	}

	if len(events) == 0 {
		return &AnalysisResult{
			Skipped:       true,
			SkippedReason: "no related file events were found",
		}, nil
	}

	actualWindowStartedAt,
		actualWindowEndedAt :=
		detectionEventWindowBounds(
			events,
		)

	detectionID := uuid.New()

	windowFingerprint :=
		buildWindowFingerprint(
			organizationID,
			triggerEvent,
			windowEndedAt.
				Truncate(
					s.windowDuration,
				),
		)

	existingDetection, existingErr :=
		s.repository.
			GetDetectionByFingerprint(
				ctx,
				organizationID,
				windowFingerprint,
			)
	if existingErr == nil {
		return &AnalysisResult{
			Detection: existingDetection,
			Created:   false,
		}, nil
	}

	if !errors.Is(
		existingErr,
		ErrDetectionNotFound,
	) {
		return nil, existingErr
	}

	window := DetectionWindow{
		ID: detectionID,

		OrganizationID: organizationID,

		DepartmentID: triggerEvent.DepartmentID,

		DeviceIdentifier: triggerEvent.DeviceIdentifier,

		DeviceName: triggerEvent.DeviceName,

		ProcessID: triggerEvent.ProcessID,

		ProcessName: triggerEvent.ProcessName,

		ExecutablePath: triggerEvent.ExecutablePath,

		ParentProcessID: triggerEvent.ParentProcessID,

		ParentProcessName: triggerEvent.ParentProcessName,

		CommandLine: triggerEvent.CommandLine,

		StartedAt: actualWindowStartedAt,

		EndedAt: actualWindowEndedAt,

		Events: events,
	}

	features, err :=
		ExtractDetectionFeatures(
			window,
			s.featurePolicy,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"extract pre-encryption features: %w",
			err,
		)
	}

	ruleAssessment, err :=
		EvaluateRuleAssessment(
			features,
			events,
			s.featurePolicy,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"evaluate pre-encryption rules: %w",
			err,
		)
	}

	var engineAssessment *DetectionEngineAssessment

	var engineErr error

	if s.engine != nil {
		engineAssessment, engineErr =
			s.engine.Assess(
				ctx,
				DetectionEngineRequest{
					RequestID: uuid.New(),

					RequestType: DetectionEngineRequestType,

					SchemaVersion: DetectionFeatureSchemaVersion,

					OrganizationID: organizationID,

					DetectionID: detectionID,

					WindowFingerprint: windowFingerprint,

					RuleScore: ruleAssessment.RuleScore,

					Features: features,

					RequestedAt: time.Now().UTC(),
				},
			)
	} else {
		engineErr =
			ErrDetectionEngineUnavailable
	}

	finalScore :=
		ruleAssessment.RuleScore

	if engineAssessment != nil {
		finalScore =
			engineAssessment.
				CombinedRiskScore
	}

	if finalScore <
		s.minimumDetectionScore {
		return &AnalysisResult{
			Skipped:        true,
			SkippedReason:  "detection score is below minimum threshold",
			EngineFallback: engineAssessment == nil,
			EngineError:    engineErr,
		}, nil
	}

	detection, err :=
		buildDetectionRecord(
			detectionID,
			organizationID,
			windowFingerprint,
			triggerEvent,
			actualWindowStartedAt,
			actualWindowEndedAt,
			features,
			ruleAssessment,
			engineAssessment,
		)
	if err != nil {
		return nil, err
	}

	createdDetection, err :=
		s.repository.CreateDetection(
			ctx,
			*detection,
			ruleAssessment.
				EventContributions,
		)
	if errors.Is(
		err,
		ErrDetectionAlreadyExists,
	) {
		existingDetection, lookupErr :=
			s.repository.
				GetDetectionByFingerprint(
					ctx,
					organizationID,
					windowFingerprint,
				)
		if lookupErr != nil {
			return nil, lookupErr
		}

		return &AnalysisResult{
			Detection:      existingDetection,
			Created:        false,
			EngineFallback: engineAssessment == nil,
			EngineError:    engineErr,
		}, nil
	}

	if err != nil {
		return nil, err
	}

	return &AnalysisResult{
		Detection:      createdDetection,
		Created:        true,
		EngineFallback: engineAssessment == nil,
		EngineError:    engineErr,
	}, nil
}

func buildDetectionRecord(
	detectionID uuid.UUID,
	organizationID uuid.UUID,
	windowFingerprint string,
	triggerEvent *FileEventObservation,
	windowStartedAt time.Time,
	windowEndedAt time.Time,
	features DetectionFeatures,
	ruleAssessment *RuleAssessment,
	engineAssessment *DetectionEngineAssessment,
) (*Detection, error) {
	if triggerEvent == nil ||
		ruleAssessment == nil {
		return nil, errors.New(
			"pre-encryption assessment data is incomplete",
		)
	}

	detectionMethod :=
		DetectionMethodRuleBased

	combinedScore :=
		ruleAssessment.RuleScore

	riskLevel :=
		ruleAssessment.RiskLevel

	classification :=
		ruleAssessment.Classification

	detectionStage :=
		ruleAssessment.DetectionStage

	scoreExplanation :=
		ruleAssessment.ScoreExplanation

	requiresHumanReview :=
		ruleAssessment.
			RequiresHumanReview

	requiresEndpointIsolation :=
		ruleAssessment.
			RequiresEndpointIsolation

	recommendedActions :=
		ruleAssessment.
			RecommendedActions

	var aiScore *float64
	var threatProbability *float64
	var confidenceScore *float64

	var modelName *string
	var modelVersion *string
	var policyVersion *string

	engineStatus := "RULE_FALLBACK"

	var aiFactors []RiskFactor

	if engineAssessment != nil {
		detectionMethod =
			DetectionMethodHybrid

		aiScore = float64Pointer(
			engineAssessment.AIScore,
		)

		combinedScore =
			engineAssessment.
				CombinedRiskScore

		threatProbability =
			float64Pointer(
				engineAssessment.
					ThreatProbability,
			)

		confidenceScore =
			float64Pointer(
				engineAssessment.
					ConfidenceScore,
			)

		riskLevel =
			engineAssessment.RiskLevel

		classification =
			engineAssessment.
				Classification

		detectionStage =
			engineAssessment.
				DetectionStage

		scoreExplanation =
			engineAssessment.
				ScoreExplanation

		requiresHumanReview =
			engineAssessment.
				RequiresHumanReview

		requiresEndpointIsolation =
			engineAssessment.
				RequiresEndpointIsolation

		aiFactors =
			engineAssessment.
				RiskFactors

		recommendedActions =
			engineAssessment.
				RecommendedActions

		modelName = stringPointer(
			engineAssessment.ModelName,
		)

		modelVersion = stringPointer(
			engineAssessment.ModelVersion,
		)

		policyVersion = stringPointer(
			engineAssessment.PolicyVersion,
		)

		engineStatus = "AVAILABLE"
	} else {
		threatProbability =
			float64Pointer(
				clampDetectionScore(
					ruleAssessment.
						RuleScore *
						1.05,
				),
			)

		fallbackConfidence :=
			clampDetectionScore(
				50 +
					float64(
						features.TotalEventCount,
					)*1.5 +
					float64(
						len(
							ruleAssessment.
								RiskFactors,
						),
					)*3,
			)

		confidenceScore =
			float64Pointer(
				fallbackConfidence,
			)
	}

	factorPayload :=
		storedRiskFactorPayload{
			SchemaVersion: DetectionFeatureSchemaVersion,

			DetectionMethod: detectionMethod,

			RuleScore: ruleAssessment.RuleScore,

			AIScore: aiScore,

			ModelName: modelName,

			ModelVersion: modelVersion,

			PolicyVersion: policyVersion,

			RuleFactors: ruleAssessment.
				RiskFactors,

			AIFactors: aiFactors,
		}

	riskFactorsJSON, err :=
		json.Marshal(
			factorPayload,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode pre-encryption risk factors: %w",
			err,
		)
	}

	recommendedActionsJSON, err :=
		json.Marshal(
			recommendedActions,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode recommended actions: %w",
			err,
		)
	}

	metadataJSON, err :=
		json.Marshal(
			detectionMetadataPayload{
				TriggerFileEventID: triggerEvent.ID,

				FeatureSchemaVersion: DetectionFeatureSchemaVersion,

				WindowFingerprint: windowFingerprint,

				EngineStatus: engineStatus,

				EventCount: features.TotalEventCount,
			},
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode detection metadata: %w",
			err,
		)
	}

	now := time.Now().UTC()

	windowDuration :=
		windowEndedAt.
			Sub(windowStartedAt).
			Seconds()

	return &Detection{
		ID: detectionID,

		DetectionCode: buildDetectionCode(
			detectionID,
			now,
		),

		DetectionFingerprint: windowFingerprint,

		OrganizationID: organizationID,

		DepartmentID: triggerEvent.DepartmentID,

		DeviceIdentifier: triggerEvent.
			DeviceIdentifier,

		DeviceName: triggerEvent.DeviceName,

		ProcessID: triggerEvent.ProcessID,

		ProcessName: triggerEvent.ProcessName,

		ExecutablePath: triggerEvent.ExecutablePath,

		ParentProcessID: triggerEvent.ParentProcessID,

		ParentProcessName: triggerEvent.
			ParentProcessName,

		CommandLine: triggerEvent.CommandLine,

		WindowStartedAt: windowStartedAt,

		WindowEndedAt: windowEndedAt,

		WindowDurationSeconds: windowDuration,

		TotalEventCount: features.TotalEventCount,

		UniqueFileCount: features.UniqueFileCount,

		UniqueExtensionCount: features.UniqueExtensionCount,

		UniqueProcessCount: features.UniqueProcessCount,

		CreatedEventCount: features.CreatedEventCount,

		ModifiedEventCount: features.ModifiedEventCount,

		RenamedEventCount: features.RenamedEventCount,

		ExtensionChangedEventCount: features.
			ExtensionChangedEventCount,

		DeletedEventCount: features.DeletedEventCount,

		HashChangedEventCount: features.HashChangedEventCount,

		PermissionChangedEventCount: features.
			PermissionChangedEventCount,

		EncryptedEventCount: features.EncryptedEventCount,

		CanaryEventCount: features.CanaryEventCount,

		HoneytokenEventCount: features.HoneytokenEventCount,

		ProtectedFileEventCount: features.ProtectedFileEventCount,

		HighEntropyWriteCount: features.HighEntropyWriteCount,

		TotalBytesChanged: features.TotalBytesChanged,

		EventRatePerMinute: features.EventRatePerMinute,

		FileChangeRatePerMinute: features.
			FileChangeRatePerMinute,

		AverageEntropyBefore: features.AverageEntropyBefore,

		AverageEntropyAfter: features.AverageEntropyAfter,

		AverageEntropyDelta: features.AverageEntropyDelta,

		RuleScore: ruleAssessment.RuleScore,

		AIScore: aiScore,

		CombinedRiskScore: combinedScore,

		ThreatProbability: threatProbability,

		ConfidenceScore: confidenceScore,

		RiskLevel: riskLevel,

		Classification: classification,

		DetectionStage: detectionStage,

		DetectionMethod: detectionMethod,

		RiskFactors: riskFactorsJSON,

		RecommendedActions: recommendedActionsJSON,

		ScoreExplanation: stringPointer(
			scoreExplanation,
		),

		ModelName: modelName,

		ModelVersion: modelVersion,

		PolicyVersion: policyVersion,

		RequiresHumanReview: requiresHumanReview,

		RequiresEndpointIsolation: requiresEndpointIsolation,

		Status: DetectionStatusOpen,

		ActionStatus: ActionStatusPending,

		Metadata: metadataJSON,

		DetectedAt: now,

		CreatedAt: now,

		UpdatedAt: now,
	}, nil
}

func detectionEventWindowBounds(
	events []FileEventObservation,
) (time.Time, time.Time) {
	startedAt :=
		events[0].OccurredAt.UTC()

	endedAt := startedAt

	for _, event := range events[1:] {
		occurredAt :=
			event.OccurredAt.UTC()

		if occurredAt.Before(startedAt) {
			startedAt = occurredAt
		}

		if occurredAt.After(endedAt) {
			endedAt = occurredAt
		}
	}

	return startedAt, endedAt
}

func buildWindowFingerprint(
	organizationID uuid.UUID,
	triggerEvent *FileEventObservation,
	windowBucket time.Time,
) string {
	parts := []string{
		organizationID.String(),
		windowBucket.UTC().
			Format(time.RFC3339Nano),
	}

	if triggerEvent != nil {
		if triggerEvent.DeviceIdentifier != nil {
			parts = append(
				parts,
				"device:"+
					strings.ToLower(
						strings.TrimSpace(
							*triggerEvent.
								DeviceIdentifier,
						),
					),
			)
		}

		if triggerEvent.ProcessID != nil {
			parts = append(
				parts,
				"pid:"+
					strconv.FormatInt(
						*triggerEvent.ProcessID,
						10,
					),
			)
		} else if triggerEvent.ProcessName != nil {
			parts = append(
				parts,
				"process:"+
					normalizeProcessName(
						*triggerEvent.
							ProcessName,
					),
			)
		}

		if len(parts) == 2 {
			parts = append(
				parts,
				"path:"+
					strings.ToLower(
						strings.TrimSpace(
							triggerEvent.FilePath,
						),
					),
			)
		}
	}

	digest := sha256.Sum256(
		[]byte(
			strings.Join(
				parts,
				"|",
			),
		),
	)

	return hex.EncodeToString(
		digest[:],
	)
}

func buildDetectionCode(
	detectionID uuid.UUID,
	detectedAt time.Time,
) string {
	compactID := strings.ToUpper(
		strings.ReplaceAll(
			detectionID.String(),
			"-",
			"",
		),
	)

	return fmt.Sprintf(
		"DDH-PRE-%s-%s",
		detectedAt.UTC().
			Format("20060102"),
		compactID[:8],
	)
}

func float64Pointer(
	value float64,
) *float64 {
	return &value
}

func stringPointer(
	value string,
) *string {
	value = strings.TrimSpace(
		value,
	)

	if value == "" {
		return nil
	}

	return &value
}
