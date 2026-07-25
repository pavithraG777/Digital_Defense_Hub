package preencryption

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

// RuleAssessment represents the deterministic Go
// pre-encryption ransomware assessment.
type RuleAssessment struct {
	RuleScore float64 `json:"rule_score"`

	RiskLevel      string `json:"risk_level"`
	Classification string `json:"classification"`
	DetectionStage string `json:"detection_stage"`

	RiskFactors []RiskFactor `json:"risk_factors"`

	RecommendedActions []RecommendedAction `json:"recommended_actions"`

	ScoreExplanation string `json:"score_explanation"`

	RequiresHumanReview       bool `json:"requires_human_review"`
	RequiresEndpointIsolation bool `json:"requires_endpoint_isolation"`

	EventContributions []EventContribution `json:"event_contributions"`
}

func EvaluateRuleAssessment(
	features DetectionFeatures,
	events []FileEventObservation,
	policy FeaturePolicy,
) (*RuleAssessment, error) {
	if features.TotalEventCount <= 0 {
		return nil, errors.New(
			"detection features must contain file events",
		)
	}

	if len(events) == 0 {
		return nil, errors.New(
			"file events are required for rule assessment",
		)
	}

	policy = normalizeFeaturePolicy(policy)

	riskFactors := make(
		[]RiskFactor,
		0,
		8,
	)

	velocityScore :=
		clampDetectionScore(
			features.EventRatePerMinute /
				(policy.HighEventRatePerMinute * 2) *
				100,
		)

	if features.HasRapidFileChanges &&
		velocityScore < 65 {
		velocityScore = 65
	}

	if features.MultipleFileChangeEventCount > 0 &&
		velocityScore < 80 {
		velocityScore = 80
	}

	riskFactors = appendRuleFactor(
		riskFactors,
		"FILE_CHANGE_VELOCITY",
		"File Change Velocity",
		"BEHAVIOUR",
		"Measures rapid and repeated file-system changes within a short time window.",
		0.18,
		velocityScore,
		features.TotalEventCount,
	)

	massModificationScore :=
		scoreFromThreshold(
			features.ModifiedEventCount+
				features.MultipleFileChangeEventCount,
			policy.MassModificationThreshold,
		)

	if features.HasMassModification &&
		massModificationScore < 75 {
		massModificationScore = 75
	}

	riskFactors = appendRuleFactor(
		riskFactors,
		"MASS_FILE_MODIFICATION",
		"Mass File Modification",
		"BEHAVIOUR",
		"Measures bulk modification activity commonly performed before or during ransomware encryption.",
		0.18,
		massModificationScore,
		features.ModifiedEventCount+
			features.MultipleFileChangeEventCount,
	)

	entropyScore := 0.0

	if features.HighEntropyWriteCount > 0 {
		entropyScore =
			clampDetectionScore(
				float64(
					features.HighEntropyWriteCount,
				) /
					float64(
						features.TotalEventCount,
					) *
					100,
			)

		if entropyScore < 70 {
			entropyScore = 70
		}
	}

	if features.AverageEntropyDelta != nil {
		deltaScore :=
			clampDetectionScore(
				*features.AverageEntropyDelta /
					policy.EntropyDeltaThreshold *
					70,
			)

		entropyScore =
			maximumDetectionScore(
				entropyScore,
				deltaScore,
			)
	}

	riskFactors = appendRuleFactor(
		riskFactors,
		"HIGH_ENTROPY_WRITES",
		"High Entropy File Writes",
		"CONTENT",
		"Measures entropy increases that may indicate encrypted or compressed file content.",
		0.16,
		entropyScore,
		features.HighEntropyWriteCount,
	)

	renameScore :=
		scoreFromThreshold(
			features.RenamedEventCount,
			policy.RapidRenameThreshold,
		)

	extensionScore :=
		scoreFromThreshold(
			features.ExtensionChangedEventCount,
			policy.ExtensionChangeThreshold,
		)

	renameAndExtensionScore :=
		maximumDetectionScore(
			renameScore,
			extensionScore,
		)

	if features.HasRansomwareExtension &&
		renameAndExtensionScore < 90 {
		renameAndExtensionScore = 90
	}

	riskFactors = appendRuleFactor(
		riskFactors,
		"RENAME_EXTENSION_ACTIVITY",
		"Rename and Extension Activity",
		"FILE_SYSTEM",
		"Measures rapid file renaming, extension replacement and known ransomware-style extensions.",
		0.14,
		renameAndExtensionScore,
		features.RenamedEventCount+
			features.ExtensionChangedEventCount+
			features.RansomwareExtensionCount,
	)

	deletionScore :=
		scoreFromThreshold(
			features.DeletedEventCount,
			policy.DeletionBurstThreshold,
		)

	hashScore :=
		scoreFromThreshold(
			features.HashChangedEventCount,
			policy.HashChangeThreshold,
		)

	permissionScore :=
		scoreFromThreshold(
			features.PermissionChangedEventCount,
			policy.PermissionChangeThreshold,
		)

	destructiveScore :=
		maximumDetectionScore(
			deletionScore,
			hashScore,
			permissionScore,
		)

	riskFactors = appendRuleFactor(
		riskFactors,
		"DESTRUCTIVE_FILE_OPERATIONS",
		"Destructive File Operations",
		"FILE_SYSTEM",
		"Measures deletion, hash replacement and permission modification bursts.",
		0.12,
		destructiveScore,
		features.DeletedEventCount+
			features.HashChangedEventCount+
			features.PermissionChangedEventCount,
	)

	deceptionScore := 0.0

	switch {
	case features.HasCanaryTrigger ||
		features.HasHoneytokenAccess:
		deceptionScore = 100

	case features.HasProtectedFileActivity:
		deceptionScore = 55
	}

	riskFactors = appendRuleFactor(
		riskFactors,
		"DECEPTION_RESOURCE_ACTIVITY",
		"Deception Resource Activity",
		"DECEPTION",
		"Measures interaction with canary files, honeytokens and protected files.",
		0.12,
		deceptionScore,
		features.CanaryEventCount+
			features.HoneytokenEventCount+
			features.ProtectedFileEventCount,
	)

	processScore := 0.0

	if features.HasSuspiciousProcess {
		processScore =
			clampDetectionScore(
				50 +
					float64(
						features.SuspiciousProcessCount,
					)*10,
			)
	}

	riskFactors = appendRuleFactor(
		riskFactors,
		"SUSPICIOUS_PROCESS_ACTIVITY",
		"Suspicious Process Activity",
		"PROCESS",
		"Measures file activity performed by processes commonly associated with destructive system changes.",
		0.05,
		processScore,
		features.SuspiciousProcessCount,
	)

	existingThreatScore :=
		clampDetectionScore(
			float64(
				features.MaximumExistingThreatScore,
			),
		)

	if features.SuspiciousEventRatio >= 0.5 &&
		existingThreatScore < 70 {
		existingThreatScore = 70
	}

	riskFactors = appendRuleFactor(
		riskFactors,
		"EXISTING_THREAT_SIGNALS",
		"Existing Threat Signals",
		"THREAT",
		"Uses existing suspicious-event flags and threat scores produced by the file-event pipeline.",
		0.05,
		existingThreatScore,
		features.SuspiciousEventCount,
	)

	ruleScore := 0.0

	for _, factor := range riskFactors {
		ruleScore += factor.Contribution
	}

	ruleScore =
		roundDetectionScore(
			clampDetectionScore(
				ruleScore,
			),
		)

	policyFloor := 0.0
	policyReason := ""

	applyPolicyFloor := func(
		score float64,
		reason string,
	) {
		if score > policyFloor {
			policyFloor = score
			policyReason = reason
		}
	}

	if features.HasEncryptionActivity {
		applyPolicyFloor(
			95,
			"An explicit encrypted file event was detected.",
		)
	}

	if features.HasHighEntropyWrites &&
		features.HasMassModification {
		applyPolicyFloor(
			88,
			"Mass file modification occurred together with high entropy writes.",
		)
	}

	if features.HasCanaryTrigger ||
		features.HasHoneytokenAccess {
		applyPolicyFloor(
			82,
			"A deception resource was accessed or modified.",
		)
	}

	if features.HasRansomwareExtension &&
		features.HasRapidFileChanges {
		applyPolicyFloor(
			80,
			"Ransomware-style extensions appeared during rapid file activity.",
		)
	}

	if features.HasMassModification &&
		features.HasRapidFileChanges {
		applyPolicyFloor(
			70,
			"Mass modification and rapid file changes occurred together.",
		)
	}

	if policyFloor > ruleScore {
		floorContribution :=
			roundDetectionScore(
				policyFloor - ruleScore,
			)

		riskFactors = append(
			riskFactors,
			RiskFactor{
				Code:         "POLICY_ESCALATION_FLOOR",
				Name:         "Security Policy Escalation",
				Category:     "POLICY",
				Description:  policyReason,
				Weight:       1,
				Score:        floorContribution,
				Contribution: floorContribution,
				SignalCount:  1,
			},
		)

		ruleScore = policyFloor
	}

	riskLevel, valid :=
		RiskLevelFromScore(
			ruleScore,
		)
	if !valid {
		return nil, errors.New(
			"unable to determine rule risk level",
		)
	}

	classification :=
		classificationFromDetectionScore(
			ruleScore,
		)

	detectionStage :=
		detectionStageFromFeatures(
			features,
		)

	recommendedActions :=
		buildRecommendedActions(
			features,
			ruleScore,
		)

	eventContributions :=
		buildEventContributions(
			events,
			features,
			policy,
		)

	requiresHumanReview :=
		ruleScore >= HighRiskThreshold ||
			features.HasCanaryTrigger ||
			features.HasHoneytokenAccess

	requiresEndpointIsolation :=
		ruleScore >= CriticalRiskThreshold ||
			features.HasEncryptionActivity ||
			features.HasCanaryTrigger ||
			features.HasHoneytokenAccess

	return &RuleAssessment{
		RuleScore: ruleScore,

		RiskLevel:      riskLevel,
		Classification: classification,
		DetectionStage: detectionStage,

		RiskFactors: riskFactors,

		RecommendedActions: recommendedActions,

		ScoreExplanation: buildRuleScoreExplanation(
			ruleScore,
			riskLevel,
			classification,
			riskFactors,
			policyReason,
		),

		RequiresHumanReview: requiresHumanReview,

		RequiresEndpointIsolation: requiresEndpointIsolation,

		EventContributions: eventContributions,
	}, nil
}

func appendRuleFactor(
	factors []RiskFactor,
	code string,
	name string,
	category string,
	description string,
	weight float64,
	score float64,
	signalCount int,
) []RiskFactor {
	score =
		roundDetectionScore(
			clampDetectionScore(
				score,
			),
		)

	if score <= 0 {
		return factors
	}

	contribution :=
		roundDetectionScore(
			score * weight,
		)

	return append(
		factors,
		RiskFactor{
			Code:         code,
			Name:         name,
			Category:     category,
			Description:  description,
			Weight:       weight,
			Score:        score,
			Contribution: contribution,
			SignalCount:  signalCount,
		},
	)
}

func scoreFromThreshold(
	count int,
	threshold int,
) float64 {
	if count <= 0 ||
		threshold <= 0 {
		return 0
	}

	return clampDetectionScore(
		float64(count) /
			float64(threshold) *
			100,
	)
}

func clampDetectionScore(
	value float64,
) float64 {
	switch {
	case math.IsNaN(value),
		math.IsInf(value, 0),
		value < MinimumScore:
		return MinimumScore

	case value > MaximumScore:
		return MaximumScore

	default:
		return value
	}
}

func roundDetectionScore(
	value float64,
) float64 {
	return math.Round(
		value*100,
	) / 100
}

func maximumDetectionScore(
	values ...float64,
) float64 {
	maximum := 0.0

	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}

	return maximum
}

func classificationFromDetectionScore(
	score float64,
) string {
	switch {
	case score >= 85:
		return ClassificationRansomware

	case score >= 60:
		return ClassificationLikelyRansomware

	case score >= MediumRiskThreshold:
		return ClassificationSuspicious

	default:
		return ClassificationBenign
	}
}

func detectionStageFromFeatures(
	features DetectionFeatures,
) string {
	switch {
	case features.HasEncryptionActivity:
		return DetectionStageEncryptionConfirmed

	case features.HasHighEntropyWrites,
		features.HasRansomwareExtension,
		features.HasExtensionChangeBurst:
		return DetectionStageEncryptionSuspected

	default:
		return DetectionStagePreEncryption
	}
}

func buildRecommendedActions(
	features DetectionFeatures,
	ruleScore float64,
) []RecommendedAction {
	actions := make(
		[]RecommendedAction,
		0,
		6,
	)

	if ruleScore < MediumRiskThreshold {
		return append(
			actions,
			RecommendedAction{
				Code:        "CONTINUE_MONITORING",
				Title:       "Continue Monitoring",
				Description: "Continue monitoring the process and file activity for behavioural escalation.",
				Priority:    RiskLevelLow,
				Automatic:   false,
			},
		)
	}

	actions = append(
		actions,
		RecommendedAction{
			Code:        "PRESERVE_FILE_EVENT_EVIDENCE",
			Title:       "Preserve File Event Evidence",
			Description: "Preserve file hashes, process information, command line data and affected file paths.",
			Priority:    RiskLevelHigh,
			Automatic:   false,
		},
	)

	if features.HasRapidFileChanges ||
		features.HasMassModification {
		actions = append(
			actions,
			RecommendedAction{
				Code:        "RESTRICT_WRITE_ACTIVITY",
				Title:       "Restrict Write Activity",
				Description: "Temporarily restrict write access for the suspicious process and affected locations.",
				Priority:    RiskLevelCritical,
				Automatic:   false,
			},
		)
	}

	if features.HasSuspiciousProcess {
		actions = append(
			actions,
			RecommendedAction{
				Code:        "SUSPEND_SUSPICIOUS_PROCESS",
				Title:       "Suspend Suspicious Process",
				Description: "Review and suspend the process responsible for destructive file activity.",
				Priority:    RiskLevelCritical,
				Automatic:   false,
			},
		)
	}

	if features.HasCanaryTrigger ||
		features.HasHoneytokenAccess {
		actions = append(
			actions,
			RecommendedAction{
				Code:        "INVESTIGATE_DECEPTION_TRIGGER",
				Title:       "Investigate Deception Trigger",
				Description: "Investigate the identity, process and device that interacted with the deception resource.",
				Priority:    RiskLevelCritical,
				Automatic:   false,
			},
		)
	}

	if ruleScore >= CriticalRiskThreshold {
		actions = append(
			actions,
			RecommendedAction{
				Code:        "ISOLATE_ENDPOINT",
				Title:       "Isolate Affected Endpoint",
				Description: "Isolate the affected endpoint after authorization to prevent additional file encryption.",
				Priority:    RiskLevelCritical,
				Automatic:   false,
			},
		)
	}

	return actions
}

func buildRuleScoreExplanation(
	ruleScore float64,
	riskLevel string,
	classification string,
	factors []RiskFactor,
	policyReason string,
) string {
	sortedFactors := append(
		[]RiskFactor(nil),
		factors...,
	)

	sort.SliceStable(
		sortedFactors,
		func(
			left int,
			right int,
		) bool {
			return sortedFactors[left].
				Contribution >
				sortedFactors[right].
					Contribution
		},
	)

	factorNames := make(
		[]string,
		0,
		3,
	)

	for _, factor := range sortedFactors {
		if factor.Code ==
			"POLICY_ESCALATION_FLOOR" {
			continue
		}

		factorNames = append(
			factorNames,
			fmt.Sprintf(
				"%s (%.2f/100)",
				factor.Name,
				factor.Score,
			),
		)

		if len(factorNames) == 3 {
			break
		}
	}

	explanation := fmt.Sprintf(
		"Pre-encryption ransomware rule score is %.2f/100, risk level is %s, and classification is %s.",
		ruleScore,
		riskLevel,
		classification,
	)

	if len(factorNames) > 0 {
		explanation +=
			" Primary contributing factors are " +
				strings.Join(
					factorNames,
					", ",
				) +
				"."
	}

	if strings.TrimSpace(
		policyReason,
	) != "" {
		explanation +=
			" Security policy escalation applied: " +
				strings.TrimSpace(
					policyReason,
				)
	}

	return explanation
}

func buildEventContributions(
	events []FileEventObservation,
	features DetectionFeatures,
	policy FeaturePolicy,
) []EventContribution {
	contributions := make(
		[]EventContribution,
		0,
		len(events),
	)

	for _, event := range events {
		signals := make(
			[]string,
			0,
			6,
		)

		eventType :=
			NormalizeConstant(
				event.EventType,
			)

		sourceType :=
			NormalizeConstant(
				event.SourceType,
			)

		if features.HasMassModification &&
			(eventType == EventTypeModified ||
				eventType == EventTypeMultipleFileChanges) {
			signals = appendUniqueSignal(
				signals,
				SignalMassFileModification,
			)
		}

		if features.HasRapidFileChanges &&
			IsFileChangeEventType(
				eventType,
			) {
			signals = appendUniqueSignal(
				signals,
				SignalRapidFileChanges,
			)
		}

		if features.HasRapidRename &&
			eventType == EventTypeRenamed {
			signals = appendUniqueSignal(
				signals,
				SignalRapidRename,
			)
		}

		if eventType ==
			EventTypeExtensionChanged {
			signals = appendUniqueSignal(
				signals,
				SignalExtensionChangeBurst,
			)
		}

		if eventType == EventTypeHashChanged {
			signals = appendUniqueSignal(
				signals,
				SignalHashChangeBurst,
			)
		}

		if eventType == EventTypeDeleted {
			signals = appendUniqueSignal(
				signals,
				SignalFileDeletionBurst,
			)
		}

		if eventType ==
			EventTypePermissionChanged {
			signals = appendUniqueSignal(
				signals,
				SignalPermissionChangeBurst,
			)
		}

		if eventType == EventTypeEncrypted {
			signals = appendUniqueSignal(
				signals,
				SignalEncryptionActivity,
			)
		}

		switch sourceType {
		case SourceTypeCanaryFile:
			signals = appendUniqueSignal(
				signals,
				SignalCanaryTrigger,
			)

		case SourceTypeHoneytoken:
			signals = appendUniqueSignal(
				signals,
				SignalHoneytokenAccess,
			)

		case SourceTypeProtectedFile:
			signals = appendUniqueSignal(
				signals,
				SignalProtectedFileActivity,
			)
		}

		entropyMetadata :=
			parseFileEventEntropyMetadata(
				event.Metadata,
			)

		entropyDelta :=
			resolveEntropyDelta(
				entropyMetadata,
			)

		if isHighEntropyWrite(
			entropyMetadata,
			entropyDelta,
			policy,
		) {
			signals = appendUniqueSignal(
				signals,
				SignalHighEntropyWrite,
			)
		}

		if isSuspiciousProcess(
			event,
			policy.SuspiciousProcessNames,
		) {
			signals = appendUniqueSignal(
				signals,
				SignalSuspiciousProcess,
			)
		}

		if features.EventRatePerMinute >=
			policy.HighEventRatePerMinute {
			signals = appendUniqueSignal(
				signals,
				SignalHighEventRate,
			)
		}

		if len(signals) == 0 {
			continue
		}

		contributions = append(
			contributions,
			EventContribution{
				FileEventID: event.ID,
				SignalTypes: signals,
				ContributionScore: scoreEventSignals(
					signals,
				),
			},
		)
	}

	return contributions
}

func appendUniqueSignal(
	signals []string,
	signal string,
) []string {
	for _, existingSignal := range signals {
		if existingSignal == signal {
			return signals
		}
	}

	return append(
		signals,
		signal,
	)
}

func scoreEventSignals(
	signals []string,
) float64 {
	score := 0.0

	for _, signal := range signals {
		switch signal {
		case SignalEncryptionActivity:
			score += 100

		case SignalCanaryTrigger,
			SignalHoneytokenAccess:
			score += 80

		case SignalHighEntropyWrite:
			score += 55

		case SignalExtensionChangeBurst:
			score += 45

		case SignalMassFileModification:
			score += 40

		case SignalRapidRename:
			score += 35

		case SignalHashChangeBurst,
			SignalFileDeletionBurst:
			score += 30

		case SignalSuspiciousProcess:
			score += 30

		case SignalPermissionChangeBurst:
			score += 25

		case SignalRapidFileChanges:
			score += 25

		case SignalProtectedFileActivity:
			score += 20

		case SignalHighEventRate:
			score += 20
		}
	}

	return roundDetectionScore(
		clampDetectionScore(
			score,
		),
	)
}
