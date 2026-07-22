package auditlog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
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
	ErrInvalidAuditLog = errors.New(
		"invalid audit log",
	)

	ErrAuditLogFailed = errors.New(
		"audit log operation failed",
	)
)

type AuditLogRepository interface {
	Create(
		ctx context.Context,
		auditLog *AuditLog,
	) error

	List(
		ctx context.Context,
	) ([]AuditLog, error)

	GetByID(
		ctx context.Context,
		id string,
	) (*AuditLog, error)
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

type LogRequest struct {
	OrganizationID *uuid.UUID
	UserID         *uuid.UUID
	SessionID      *uuid.UUID

	ModuleName string
	ActionName string

	EntityType string
	EntityID   *uuid.UUID

	Description string

	OldValues map[string]any
	NewValues map[string]any
	Metadata  map[string]any

	IPAddress  string
	DeviceName string
	UserAgent  string

	RiskLevel string

	FailureReason string
}

func (s *Service) Log(
	ctx context.Context,
	auditLog *AuditLog,
) error {
	if s == nil {
		return fmt.Errorf(
			"%w: audit service cannot be nil",
			ErrAuditLogFailed,
		)
	}

	if s.repository == nil {
		return fmt.Errorf(
			"%w: audit repository cannot be nil",
			ErrAuditLogFailed,
		)
	}

	if auditLog == nil {
		return fmt.Errorf(
			"%w: audit log cannot be nil",
			ErrInvalidAuditLog,
		)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if err := validateAuditLog(auditLog); err != nil {
		return err
	}

	prepareAuditLog(auditLog)

	if err := s.repository.Create(
		ctx,
		auditLog,
	); err != nil {
		return fmt.Errorf(
			"%w: %v",
			ErrAuditLogFailed,
			err,
		)
	}

	return nil
}

func (s *Service) LogSuccess(
	ctx context.Context,
	request LogRequest,
) {
	if s == nil {
		return
	}

	fillRequestDetailsFromContext(
		ctx,
		&request,
	)

	fmt.Println("================================")
	fmt.Println("AUDIT LOG SUCCESS CONTEXT")
	fmt.Println("IP Address:", request.IPAddress)
	fmt.Println("Device Name:", request.DeviceName)
	fmt.Println("User Agent:", request.UserAgent)
	fmt.Println("Session ID:", request.SessionID)
	fmt.Println("================================")

	auditEntry := &AuditLog{
		OrganizationID: request.OrganizationID,
		UserID:         request.UserID,
		SessionID:      request.SessionID,

		ModuleName: request.ModuleName,
		ActionName: request.ActionName,

		EntityType: request.EntityType,
		EntityID:   request.EntityID,

		Description: request.Description,

		OldValues: request.OldValues,
		NewValues: request.NewValues,
		Metadata:  request.Metadata,

		IPAddress:  request.IPAddress,
		DeviceName: request.DeviceName,
		UserAgent:  request.UserAgent,

		ResultStatus: ResultStatusSuccess,
		RiskLevel:    request.RiskLevel,
	}

	if err := s.Log(
		ctx,
		auditEntry,
	); err != nil {
		fmt.Println(
			"AUDIT LOG SUCCESS INSERT ERROR:",
			err,
		)

		return
	}

	fmt.Println(
		"AUDIT LOG SUCCESS INSERTED:",
		auditEntry.ID,
	)
}

func (s *Service) LogFailure(
	ctx context.Context,
	request LogRequest,
) {
	if s == nil {
		return
	}

	fillRequestDetailsFromContext(
		ctx,
		&request,
	)

	fmt.Println("================================")
	fmt.Println("AUDIT LOG FAILURE CONTEXT")
	fmt.Println("IP Address:", request.IPAddress)
	fmt.Println("Device Name:", request.DeviceName)
	fmt.Println("User Agent:", request.UserAgent)
	fmt.Println("Session ID:", request.SessionID)
	fmt.Println("================================")

	auditEntry := &AuditLog{
		OrganizationID: request.OrganizationID,
		UserID:         request.UserID,
		SessionID:      request.SessionID,

		ModuleName: request.ModuleName,
		ActionName: request.ActionName,

		EntityType: request.EntityType,
		EntityID:   request.EntityID,

		Description: request.Description,

		OldValues: request.OldValues,
		NewValues: request.NewValues,
		Metadata:  request.Metadata,

		IPAddress:  request.IPAddress,
		DeviceName: request.DeviceName,
		UserAgent:  request.UserAgent,

		ResultStatus: ResultStatusFailed,
		RiskLevel:    request.RiskLevel,

		FailureReason: request.FailureReason,
	}

	if err := s.Log(
		ctx,
		auditEntry,
	); err != nil {
		fmt.Println(
			"AUDIT LOG FAILURE INSERT ERROR:",
			err,
		)

		return
	}

	fmt.Println(
		"AUDIT LOG FAILURE INSERTED:",
		auditEntry.ID,
	)
}

func (s *Service) ListAuditLogs(
	ctx context.Context,
) ([]AuditLog, error) {
	if s == nil {
		return nil, fmt.Errorf(
			"%w: audit service cannot be nil",
			ErrAuditLogFailed,
		)
	}

	if s.repository == nil {
		return nil, fmt.Errorf(
			"%w: audit repository cannot be nil",
			ErrAuditLogFailed,
		)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	auditLogs, err := s.repository.List(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to list audit logs: %v",
			ErrAuditLogFailed,
			err,
		)
	}

	return auditLogs, nil
}

func (s *Service) GetAuditLogByID(
	ctx context.Context,
	id string,
) (*AuditLog, error) {
	if s == nil {
		return nil, fmt.Errorf(
			"%w: audit service cannot be nil",
			ErrAuditLogFailed,
		)
	}

	if s.repository == nil {
		return nil, fmt.Errorf(
			"%w: audit repository cannot be nil",
			ErrAuditLogFailed,
		)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	id = strings.TrimSpace(id)

	if id == "" {
		return nil, fmt.Errorf(
			"%w: audit log id is required",
			ErrInvalidAuditLog,
		)
	}

	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf(
			"%w: audit log id must be a valid UUID",
			ErrInvalidAuditLog,
		)
	}

	auditLog, err := s.repository.GetByID(
		ctx,
		id,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to get audit log: %v",
			ErrAuditLogFailed,
			err,
		)
	}

	return auditLog, nil
}

func fillRequestDetailsFromContext(
	ctx context.Context,
	request *LogRequest,
) {
	if request == nil || ctx == nil {
		return
	}

	if strings.TrimSpace(request.IPAddress) == "" {
		request.IPAddress = GetRequestIPAddress(
			ctx,
		)
	}

	if strings.TrimSpace(request.DeviceName) == "" {
		request.DeviceName = GetRequestDeviceName(
			ctx,
		)
	}

	if strings.TrimSpace(request.UserAgent) == "" {
		request.UserAgent = GetRequestUserAgent(
			ctx,
		)
	}

	if request.SessionID == nil {
		request.SessionID = GetRequestSessionID(
			ctx,
		)
	}
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

	if strings.TrimSpace(auditLog.ResultStatus) != "" &&
		!isValidResultStatus(
			auditLog.ResultStatus,
		) {
		return fmt.Errorf(
			"%w: result status must be SUCCESS or FAILED",
			ErrInvalidAuditLog,
		)
	}

	if strings.TrimSpace(auditLog.RiskLevel) != "" &&
		!isValidRiskLevel(
			auditLog.RiskLevel,
		) {
		return fmt.Errorf(
			"%w: risk level must be LOW, MEDIUM, HIGH or CRITICAL",
			ErrInvalidAuditLog,
		)
	}

	if strings.EqualFold(
		strings.TrimSpace(
			auditLog.ResultStatus,
		),
		ResultStatusFailed,
	) &&
		strings.TrimSpace(
			auditLog.FailureReason,
		) == "" {
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
		strings.TrimSpace(
			auditLog.ModuleName,
		),
	)

	auditLog.ActionName = strings.ToUpper(
		strings.TrimSpace(
			auditLog.ActionName,
		),
	)

	auditLog.EntityType = strings.ToUpper(
		strings.TrimSpace(
			auditLog.EntityType,
		),
	)

	auditLog.Description = strings.TrimSpace(
		auditLog.Description,
	)

	auditLog.IPAddress = strings.TrimSpace(
		auditLog.IPAddress,
	)

	auditLog.DeviceName = strings.TrimSpace(
		auditLog.DeviceName,
	)

	auditLog.UserAgent = strings.TrimSpace(
		auditLog.UserAgent,
	)

	auditLog.FailureReason = strings.TrimSpace(
		auditLog.FailureReason,
	)

	if strings.TrimSpace(
		auditLog.ResultStatus,
	) == "" {
		auditLog.ResultStatus = ResultStatusSuccess
	} else {
		auditLog.ResultStatus = strings.ToUpper(
			strings.TrimSpace(
				auditLog.ResultStatus,
			),
		)
	}

	if strings.TrimSpace(
		auditLog.RiskLevel,
	) == "" {
		auditLog.RiskLevel = RiskLevelLow
	} else {
		auditLog.RiskLevel = strings.ToUpper(
			strings.TrimSpace(
				auditLog.RiskLevel,
			),
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
		strings.TrimSpace(
			resultStatus,
		),
	) {
	case ResultStatusSuccess,
		ResultStatusFailed:
		return true

	default:
		return false
	}
}

func isValidRiskLevel(
	riskLevel string,
) bool {
	switch strings.ToUpper(
		strings.TrimSpace(
			riskLevel,
		),
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

		sanitizedValues[key] = sanitizeValue(
			value,
		)
	}

	return sanitizedValues
}

func sanitizeValue(
	value any,
) any {
	switch typedValue := value.(type) {
	case map[string]any:
		return sanitizeSensitiveValues(
			typedValue,
		)

	case []any:
		sanitizedItems := make(
			[]any,
			len(typedValue),
		)

		for index, item := range typedValue {
			sanitizedItems[index] = sanitizeValue(
				item,
			)
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
		strings.TrimSpace(
			key,
		),
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
