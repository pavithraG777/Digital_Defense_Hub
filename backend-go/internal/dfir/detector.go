package dfir

import (
	"fmt"
	"strings"
)

// defaultDetectionRules returns a defensively-scoped rule set covering common
// ransomware and suspicious behavior patterns.
func defaultDetectionRules() []DetectionRule {
	return []DetectionRule{
		{ID: "RAPID_FILE_ENCRYPTION", Name: "Rapid file encryption", Description: "Many files rewritten in a short interval", Signals: map[string]float64{"rapid_file_encryption": 1}, Weight: 35, Confidence: 0.85, RiskLevel: RiskLevelHigh},
		{ID: "CANARY_ACCESS", Name: "Canary access", Description: "Defensive canary file or honeytrack triggered", Signals: map[string]float64{"canary_access": 1, "honeytoken_trigger": 1}, Weight: 25, Confidence: 0.9, RiskLevel: RiskLevelHigh},
		{ID: "SHADOW_COPY_DELETION", Name: "Shadow copy deletion", Description: "Backup or volume shadow copy removal", Signals: map[string]float64{"shadow_copy_deletion": 1, "backup_deletion": 1}, Weight: 22, Confidence: 0.88, RiskLevel: RiskLevelHigh},
		{ID: "POWERSHELL", Name: "Suspicious PowerShell", Description: "PowerShell or script execution associated with suspicious activity", Signals: map[string]float64{"suspicious_powershell": 1}, Weight: 18, Confidence: 0.76, RiskLevel: RiskLevelMedium},
		{ID: "NETWORK_SPIKE", Name: "Unusual network transfer", Description: "Exfiltration or staging burst detected", Signals: map[string]float64{"unusual_network_transfer": 1}, Weight: 14, Confidence: 0.7, RiskLevel: RiskLevelMedium},
		{ID: "PRIVILEGE_ESCALATION", Name: "Privilege escalation", Description: "Potential privilege escalation pattern", Signals: map[string]float64{"privilege_escalation": 1}, Weight: 20, Confidence: 0.8, RiskLevel: RiskLevelHigh},
		{ID: "FILE_RENAME_BURST", Name: "Rapid rename burst", Description: "Mass rename activity often seen during ransomware staging", Signals: map[string]float64{"rapid_rename": 1}, Weight: 17, Confidence: 0.7, RiskLevel: RiskLevelMedium},
	}
}

// DetectSignals produces a normalized finding by matching event-derived signals to a rule base.
func DetectSignals(signals []string, evidenceCount int) DetectionFinding {
	if len(signals) == 0 && evidenceCount == 0 {
		return DetectionFinding{MatchedSignals: nil, RuleScores: map[string]float64{}, Score: 0, RiskLevel: RiskLevelLow, Confidence: 0.2, Summary: "No suspicious indicators were observed."}
	}

	matched := make(map[string]float64)
	matchedSignals := make([]string, 0)
	seen := map[string]struct{}{}
	for _, signal := range signals {
		key := strings.ToLower(strings.TrimSpace(signal))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		matchedSignals = append(matchedSignals, key)
	}

	for _, rule := range defaultDetectionRules() {
		var ruleScore float64
		for signalName := range rule.Signals {
			for _, signal := range matchedSignals {
				if signal == strings.ToLower(signalName) {
					ruleScore += rule.Signals[signalName]
				}
			}
		}
		if ruleScore > 0 {
			matched[rule.ID] = rule.Weight + ruleScore*10
		}
	}

	total := 0.0
	for _, score := range matched {
		total += score
	}
	if evidenceCount > 0 {
		total += float64(min(evidenceCount, 25)) * 1.5
	}

	confidence := 0.55
	if len(matchedSignals) > 0 {
		confidence = 0.55 + (float64(len(matchedSignals)) * 0.06)
	}
	if confidence > 0.96 {
		confidence = 0.96
	}

	risk := RiskLevelLow
	switch {
	case total >= 80:
		risk = RiskLevelCritical
	case total >= 55:
		risk = RiskLevelHigh
	case total >= 28:
		risk = RiskLevelMedium
	}

	return DetectionFinding{
		MatchedSignals: matchedSignals,
		RuleScores:     matched,
		Score:          total,
		RiskLevel:      risk,
		Confidence:     confidence,
		Summary:        fmt.Sprintf("Detected %d suspicious indicators with a defensive risk score of %.1f.", len(matchedSignals), total),
		RuleCount:      len(matched),
	}
}
