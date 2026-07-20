package auditlog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ResultStatusSuccess = "SUCCESS"
	ResultStatusFailed  = "FAILED"

	RiskLevelLow      = "LOW"
	RiskLevelMedium   = "MEDIUM"
	RiskLevelHigh     = "HIGH"
	RiskLevelCritical = "CRITICAL"
)

var (
	ErrInvalidAuditLog = errors.New("invalid audit log")
	ErrAuditLogFailed  = errors.New("audit log operation failed")
)

type AuditLogRepository interface {
	Create(
		ctx context.Context,
		auditLog *AuditLog,
	) error
}

type Service struct {
	repository AuditLogRepository
}

func NewService(
	repository AuditLogRepository,
) *Service {
	return &Service{
		repository: repository,
	}
}

func (s *Service) Log(
	ctx context.Context,
	auditLog *AuditLog,
) error {
	if auditLog == nil {
		return fmt.Errorf(
			"%w: audit log cannot be nil",
			ErrInvalidAuditLog,
		)
	}

	if err := validateAuditLog(auditLog); err != nil {
		return err
	}

	prepareAuditLog(auditLog)

	if err := s.repository.Create(ctx, auditLog); err != nil {
		return fmt.Errorf(
			"%w: %v",
			ErrAuditLogFailed,
			err,
		)
	}

	return nil
}

func validateAuditLog(
	auditLog *AuditLog,
) error {
	if strings.TrimSpace(auditLog.ModuleName) == "" {
		return fmt.Errorf(
			"%w: module name is required",
			ErrInvalidAuditLog,
		)
	}

	if strings.TrimSpace(auditLog.ActionName) == "" {
		return fmt.Errorf(
			"%w: action name is required",
			ErrInvalidAuditLog,
		)
	}

	if auditLog.ResultStatus != "" &&
		!isValidResultStatus(auditLog.ResultStatus) {
		return fmt.Errorf(
			"%w: result status must be SUCCESS or FAILED",
			ErrInvalidAuditLog,
		)
	}

	if auditLog.RiskLevel != "" &&
		!isValidRiskLevel(auditLog.RiskLevel) {
		return fmt.Errorf(
			"%w: risk level must be LOW, MEDIUM, HIGH or CRITICAL",
			ErrInvalidAuditLog,
		)
	}

	if strings.EqualFold(
		strings.TrimSpace(auditLog.ResultStatus),
		ResultStatusFailed,
	) &&
		strings.TrimSpace(auditLog.FailureReason) == "" {
		return fmt.Errorf(
			"%w: failure reason is required for failed audit logs",
			ErrInvalidAuditLog,
		)
	}

	return nil
}

func prepareAuditLog(
	auditLog *AuditLog,
) {
	auditLog.ModuleName = strings.ToUpper(
		strings.TrimSpace(auditLog.ModuleName),
	)

	auditLog.ActionName = strings.ToUpper(
		strings.TrimSpace(auditLog.ActionName),
	)

	auditLog.EntityType = strings.ToUpper(
		strings.TrimSpace(auditLog.EntityType),
	)

	auditLog.Description = strings.TrimSpace(
		auditLog.Description,
	)

	auditLog.DeviceName = strings.TrimSpace(
		auditLog.DeviceName,
	)

	auditLog.UserAgent = strings.TrimSpace(
		auditLog.UserAgent,
	)

	auditLog.IPAddress = strings.TrimSpace(
		auditLog.IPAddress,
	)

	auditLog.FailureReason = strings.TrimSpace(
		auditLog.FailureReason,
	)

	if strings.TrimSpace(auditLog.ResultStatus) == "" {
		auditLog.ResultStatus = ResultStatusSuccess
	} else {
		auditLog.ResultStatus = strings.ToUpper(
			strings.TrimSpace(auditLog.ResultStatus),
		)
	}

	if strings.TrimSpace(auditLog.RiskLevel) == "" {
		auditLog.RiskLevel = RiskLevelLow
	} else {
		auditLog.RiskLevel = strings.ToUpper(
			strings.TrimSpace(auditLog.RiskLevel),
		)
	}

	if auditLog.OccurredAt.IsZero() {
		auditLog.OccurredAt = time.Now().UTC()
	}

	auditLog.OldValues = sanitizeSensitiveValues(
		auditLog.OldValues,
	)

	auditLog.NewValues = sanitizeSensitiveValues(
		auditLog.NewValues,
	)

	auditLog.Metadata = sanitizeSensitiveValues(
		auditLog.Metadata,
	)
}

func isValidResultStatus(
	resultStatus string,
) bool {
	switch strings.ToUpper(
		strings.TrimSpace(resultStatus),
	) {
	case ResultStatusSuccess, ResultStatusFailed:
		return true
	default:
		return false
	}
}

func isValidRiskLevel(
	riskLevel string,
) bool {
	switch strings.ToUpper(
		strings.TrimSpace(riskLevel),
	) {
	case RiskLevelLow,
		RiskLevelMedium,
		RiskLevelHigh,
		RiskLevelCritical:
		return true
	default:
		return false
	}
}

func sanitizeSensitiveValues(
	values map[string]any,
) map[string]any {
	if values == nil {
		return map[string]any{}
	}

	sanitizedValues := make(
		map[string]any,
		len(values),
	)

	for key, value := range values {
		if isSensitiveKey(key) {
			sanitizedValues[key] = "[REDACTED]"
			continue
		}

		sanitizedValues[key] = sanitizeValue(value)
	}

	return sanitizedValues
}

func sanitizeValue(
	value any,
) any {
	switch typedValue := value.(type) {
	case map[string]any:
		return sanitizeSensitiveValues(typedValue)

	case []any:
		sanitizedItems := make(
			[]any,
			len(typedValue),
		)

		for index, item := range typedValue {
			sanitizedItems[index] = sanitizeValue(item)
		}

		return sanitizedItems

	default:
		return value
	}
}

func isSensitiveKey(
	key string,
) bool {
	normalizedKey := strings.ToLower(
		strings.TrimSpace(key),
	)

	sensitiveKeys := map[string]struct{}{
		"password":         {},
		"password_hash":    {},
		"confirm_password": {},
		"access_token":     {},
		"refresh_token":    {},
		"token":            {},
		"jwt":              {},
		"secret":           {},
		"api_key":          {},
		"authorization":    {},
		"cookie":           {},
		"session_token":    {},
	}

	_, exists := sensitiveKeys[normalizedKey]

	return exists
}
