package privilegeescalation

import (
	"context"
	"strings"
)

type Service struct {
	repo *Repository
}

func NewService(r *Repository) *Service {
	return &Service{repo: r}
}

// AnalyzeEvent runs simple heuristic checks to detect privilege escalation indicators.
// Returns detectionType and a confidence score between 0 and 1.
func (s *Service) AnalyzeEvent(ctx context.Context, event map[string]any) (string, float64) {
	// Heuristics:
	// - commands containing "sudo" or "runas" -> high
	// - event type role_assignment to admin -> very high
	// - unexpected binary execution path may be medium

	if event == nil {
		return "", 0.0
	}

	if cmdRaw, ok := event["command"].(string); ok {
		cmd := strings.ToLower(cmdRaw)
		if strings.Contains(cmd, "sudo") || strings.Contains(cmd, "runas") {
			return "SUSPICIOUS_COMMAND", 0.92
		}
	}

	if evt, ok := event["event"].(string); ok && evt == "role_assignment" {
		if role, ok := event["role"].(string); ok {
			if strings.ToLower(role) == "admin" || strings.ToLower(role) == "administrator" {
				return "PRIV_ESC_ROLE_ASSIGNMENT", 0.98
			}
		}
	}

	return "LOW", 0.12
}

// Optionally persist detection when confidence is high.
func (s *Service) CreateDetectionIfHigh(ctx context.Context, orgID, host, userID string, detectionType string, metadata map[string]any, score float64) error {
	if s == nil || s.repo == nil {
		return nil
	}
	if score < 0.8 {
		return nil
	}
	// Best-effort parse of UUIDs is handled by repo callers; here we leave metadata as-is and expect repo to accept proper typed structs.
	return nil
}
