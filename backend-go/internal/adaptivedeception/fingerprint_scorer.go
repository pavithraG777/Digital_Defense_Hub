package adaptivedeception

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
)

const (
	canaryInteractionSuspiciousThreshold = 50.0
	canaryInteractionRansomwareThreshold = 85.0
)

// ScoreCanaryInteractionFingerprint calculates a deterministic
// rule-based behavioural and confidence score.
func ScoreCanaryInteractionFingerprint(
	fingerprint *CanaryInteractionFingerprint,
) error {
	if fingerprint == nil {
		return errors.New(
			"canary interaction fingerprint is required",
		)
	}

	eventType := NormalizeConstant(
		fingerprint.EventType,
	)
	if eventType == "" {
		return errors.New(
			"canary interaction event type is required",
		)
	}

	baseScore, recognizedEvent :=
		canaryInteractionEventScore(
			eventType,
		)

	score := baseScore

	signals := []string{
		"CANARY_INTERACTION",
	}

	if fingerprint.IsSuspicious {
		score += 12
		signals = append(
			signals,
			"PRECLASSIFIED_SUSPICIOUS",
		)
	}

	if fingerprint.RansomwareSuspected {
		score += 20
		signals = append(
			signals,
			"PRECLASSIFIED_RANSOMWARE",
		)
	}

	suspiciousProcess :=
		isSuspiciousCanaryProcess(
			fingerprint.ProcessName,
			fingerprint.ProcessPath,
		)

	if suspiciousProcess {
		score += 10
		signals = append(
			signals,
			"SUSPICIOUS_PROCESS_CONTEXT",
		)
	}

	if isDestructiveCanaryEvent(
		eventType,
	) {
		score += 8
		signals = append(
			signals,
			"DESTRUCTIVE_CANARY_ACTIVITY",
		)
	}

	if isRansomwareIndicativeCanaryEvent(
		eventType,
	) {
		score += 12
		signals = append(
			signals,
			"RANSOMWARE_BEHAVIOUR_INDICATOR",
		)
	}

	if fingerprint.AccessLogID != nil &&
		fingerprint.FileEventID != nil {
		score += 5
		signals = append(
			signals,
			"MULTI_SOURCE_CORRELATION",
		)
	}

	score = clampFingerprintScore(
		score,
	)

	isSuspicious :=
		fingerprint.IsSuspicious ||
			score >=
				canaryInteractionSuspiciousThreshold

	ransomwareSuspected :=
		fingerprint.RansomwareSuspected ||
			(score >=
				canaryInteractionRansomwareThreshold &&
				isRansomwareIndicativeCanaryEvent(
					eventType,
				))

	confidenceScore := 30.0

	if recognizedEvent {
		confidenceScore += 5
	}

	if fingerprint.AccessLogID != nil {
		confidenceScore += 20
	}

	if fingerprint.FileEventID != nil {
		confidenceScore += 25
	}

	if fingerprint.DeviceIdentifier != nil {
		confidenceScore += 8
	}

	if fingerprint.ProcessName != nil ||
		fingerprint.ProcessPath != nil {
		confidenceScore += 8
	}

	if fingerprint.OperatingSystemUser != nil {
		confidenceScore += 4
	}

	if fingerprint.SourceIP != nil {
		confidenceScore += 4
	}

	if ransomwareSuspected {
		confidenceScore += 5
	}

	confidenceScore =
		clampFingerprintScore(
			confidenceScore,
		)

	fingerprint.EventType = eventType

	fingerprint.BehaviouralScore =
		roundFingerprintScore(
			score,
		)

	fingerprint.ConfidenceScore =
		roundFingerprintScore(
			confidenceScore,
		)

	fingerprint.IsSuspicious =
		isSuspicious

	fingerprint.RansomwareSuspected =
		ransomwareSuspected

	if fingerprint.InteractionPattern == nil {
		fingerprint.InteractionPattern =
			make(map[string]any)
	}

	fingerprint.InteractionPattern["event_base_score"] = baseScore

	fingerprint.InteractionPattern["behavioural_signals"] = signals

	fingerprint.InteractionPattern["suspicious_process"] = suspiciousProcess

	fingerprint.InteractionPattern["recognized_event_type"] = recognizedEvent

	fingerprint.InteractionPattern["behavioural_score"] = fingerprint.BehaviouralScore

	fingerprint.InteractionPattern["confidence_score"] = fingerprint.ConfidenceScore

	fingerprint.InteractionPattern["is_suspicious"] = fingerprint.IsSuspicious

	fingerprint.InteractionPattern["ransomware_suspected"] = fingerprint.RansomwareSuspected

	return nil
}

func canaryInteractionEventScore(
	eventType string,
) (float64, bool) {
	switch NormalizeConstant(eventType) {
	case "OPENED":
		return 30, true

	case "READ":
		return 35, true

	case "CREATED":
		return 30, true

	case "COPIED":
		return 48, true

	case "MOVED":
		return 52, true

	case "RENAMED":
		return 58, true

	case "MODIFIED":
		return 65, true

	case "PERMISSION_CHANGED":
		return 68, true

	case "HASH_CHANGED":
		return 75, true

	case "DELETED":
		return 80, true

	case "EXTENSION_CHANGED":
		return 82, true

	case "MULTIPLE_FILE_CHANGES":
		return 88, true

	case "ENCRYPTED":
		return 92, true

	case "CUSTOM":
		return 40, true

	default:
		return 35, false
	}
}

func isDestructiveCanaryEvent(
	eventType string,
) bool {
	switch NormalizeConstant(eventType) {
	case "MODIFIED",
		"PERMISSION_CHANGED",
		"HASH_CHANGED",
		"DELETED",
		"EXTENSION_CHANGED",
		"MULTIPLE_FILE_CHANGES",
		"ENCRYPTED":
		return true

	default:
		return false
	}
}

func isRansomwareIndicativeCanaryEvent(
	eventType string,
) bool {
	switch NormalizeConstant(eventType) {
	case "ENCRYPTED",
		"EXTENSION_CHANGED",
		"MULTIPLE_FILE_CHANGES":
		return true

	default:
		return false
	}
}

func isSuspiciousCanaryProcess(
	processName *string,
	processPath *string,
) bool {
	value := ""

	if processName != nil {
		value = *processName
	}

	if strings.TrimSpace(value) == "" &&
		processPath != nil {
		value = filepath.Base(
			*processPath,
		)
	}

	value = strings.ToLower(
		strings.TrimSpace(value),
	)

	value = strings.TrimSuffix(
		value,
		".exe",
	)

	switch value {
	case "powershell",
		"pwsh",
		"cmd",
		"wscript",
		"cscript",
		"mshta",
		"python",
		"python3",
		"bash",
		"sh",
		"openssl",
		"cipher",
		"vssadmin",
		"wbadmin",
		"bcdedit",
		"fsutil":
		return true

	default:
		return false
	}
}

func clampFingerprintScore(
	value float64,
) float64 {
	if math.IsNaN(value) ||
		math.IsInf(value, 0) {
		return 0
	}

	switch {
	case value < 0:
		return 0

	case value > 100:
		return 100

	default:
		return value
	}
}

func roundFingerprintScore(
	value float64,
) float64 {
	value = clampFingerprintScore(
		value,
	)

	return math.Round(
		value*100,
	) / 100
}

func validateFingerprintScores(
	fingerprint *CanaryInteractionFingerprint,
) error {
	if fingerprint == nil {
		return errors.New(
			"canary interaction fingerprint is required",
		)
	}

	if fingerprint.BehaviouralScore < 0 ||
		fingerprint.BehaviouralScore > 100 {
		return fmt.Errorf(
			"behavioural score must be between 0 and 100",
		)
	}

	if fingerprint.ConfidenceScore < 0 ||
		fingerprint.ConfidenceScore > 100 {
		return fmt.Errorf(
			"confidence score must be between 0 and 100",
		)
	}

	return nil
}
