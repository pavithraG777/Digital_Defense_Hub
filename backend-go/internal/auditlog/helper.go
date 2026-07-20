package auditlog

import (
	"context"

	"github.com/google/uuid"
)

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

	RiskLevel string

	FailureReason string
}

func (s *Service) LogSuccess(
	ctx context.Context,
	request LogRequest,
) {
	if s == nil {
		return
	}

	_ = s.Log(
		ctx,
		&AuditLog{
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

			ResultStatus: ResultStatusSuccess,
			RiskLevel:    request.RiskLevel,
		},
	)
}

func (s *Service) LogFailure(
	ctx context.Context,
	request LogRequest,
) {
	if s == nil {
		return
	}

	_ = s.Log(
		ctx,
		&AuditLog{
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

			ResultStatus: ResultStatusFailed,
			RiskLevel:    request.RiskLevel,

			FailureReason: request.FailureReason,
		},
	)
}
