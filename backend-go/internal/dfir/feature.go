package dfir

import (
	"strings"
)

// inferSignalsFromEvent looks for known keys in the incoming event to produce
// a best-effort list of string signals used by rule-based scoring.
func inferSignalsFromEvent(event map[string]interface{}) []string {
	var signals []string
	if b, ok := event["canary_access"].(bool); ok && b {
		signals = append(signals, "canary_access")
	}
	if b, ok := event["honeytoken_hit"].(bool); ok && b {
		signals = append(signals, "honeytoken_trigger")
	}
	if v, ok := event["honeytoken_hits"].(float64); ok && v > 0 {
		signals = append(signals, "honeytoken_trigger")
	}
	if b, ok := event["file_encrypted"].(bool); ok && b {
		signals = append(signals, "rapid_file_encryption")
	}
	if b, ok := event["shadow_copy_deleted"].(bool); ok && b {
		signals = append(signals, "shadow_copy_deletion")
	}
	if b, ok := event["backup_deletion"].(bool); ok && b {
		signals = append(signals, "backup_deletion")
	}
	if v, ok := event["backup_deletion_count"].(float64); ok && v > 0 {
		signals = append(signals, "backup_deletion")
	}
	if b, ok := event["rapid_rename"].(bool); ok && b {
		signals = append(signals, "rapid_rename")
	}
	if v, ok := event["rename_rate"].(float64); ok && v >= 0.75 {
		signals = append(signals, "rapid_rename")
	}
	if b, ok := event["privilege_escalation"].(bool); ok && b {
		signals = append(signals, "privilege_escalation")
	}
	if b, ok := event["failed_login"].(bool); ok && b {
		signals = append(signals, "failed_login")
	}
	if v, ok := event["failed_login_count"].(float64); ok && v >= 5 {
		signals = append(signals, "failed_login")
	}
	if s, ok := event["command"].(string); ok && containsPowerShell(s) {
		signals = append(signals, "suspicious_powershell")
	}
	if n, ok := event["network_transfer_mb"].(float64); ok && n > 50.0 {
		signals = append(signals, "unusual_network_transfer")
	}
	if n, ok := event["network_spike_ratio"].(float64); ok && n >= 0.8 {
		signals = append(signals, "unusual_network_transfer")
	}
	return uniqueStrings(signals)
}

func containsPowerShell(command string) bool {
	normalized := strings.ToLower(strings.TrimSpace(command))
	return strings.Contains(normalized, "powershell") || strings.Contains(normalized, "pwsh")
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// buildFeaturePayloadFromEvent normalizes a subset of numeric features for ML.
func buildFeaturePayloadFromEvent(event map[string]interface{}) map[string]float64 {
	out := map[string]float64{}
	if v, ok := event["file_event_rate"].(float64); ok {
		out["file_event_rate"] = v
	}
	if v, ok := event["rename_rate"].(float64); ok {
		out["rename_rate"] = v
	}
	if v, ok := event["entropy_change"].(float64); ok {
		out["entropy_change"] = v
	}
	if v, ok := event["network_spike_ratio"].(float64); ok {
		out["network_spike_ratio"] = v
	}
	if v, ok := event["honeytoken_hits"].(float64); ok {
		out["honeytoken_hits"] = v
	}
	if v, ok := event["process_anomaly_score"].(float64); ok {
		out["process_anomaly_score"] = v
	}
	if v, ok := event["time_window_score"].(float64); ok {
		out["time_window_score"] = v
	}
	if b, ok := event["canary_access"].(bool); ok && b {
		out["canary_access"] = 1.0
	}
	if b, ok := event["honeytoken_hit"].(bool); ok && b {
		out["honeytoken_trigger"] = 1.0
	}
	if b, ok := event["privilege_escalation"].(bool); ok && b {
		out["privilege_escalation"] = 1.0
	}
	if b, ok := event["file_encrypted"].(bool); ok && b {
		out["rapid_file_encryption"] = 1.0
	}
	if b, ok := event["shadow_copy_deleted"].(bool); ok && b {
		out["shadow_copy_deletion"] = 1.0
	}
	if b, ok := event["backup_deletion"].(bool); ok && b {
		out["backup_deletion"] = 1.0
	}
	if v, ok := event["backup_deletion_count"].(float64); ok {
		out["backup_deletion_count"] = v
	}
	if b, ok := event["rapid_rename"].(bool); ok && b {
		out["rapid_rename"] = 1.0
	}
	if v, ok := event["failed_login_count"].(float64); ok {
		out["failed_login_count"] = v
	}
	if v, ok := event["network_transfer_mb"].(float64); ok {
		out["network_transfer_mb"] = v
	}
	if s, ok := event["command"].(string); ok && containsPowerShell(s) {
		out["powershell_command"] = 1.0
	}
	// ensure defaults for missing keys to avoid nils
	keys := []string{
		"file_event_rate", "rename_rate", "entropy_change", "network_spike_ratio",
		"honeytoken_hits", "process_anomaly_score", "time_window_score",
		"canary_access", "honeytoken_trigger", "privilege_escalation",
		"rapid_file_encryption", "shadow_copy_deletion", "backup_deletion",
		"backup_deletion_count", "rapid_rename", "failed_login_count",
		"network_transfer_mb", "powershell_command",
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			out[k] = 0.0
		}
	}
	return out
}
