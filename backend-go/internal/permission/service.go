package permission

import (
	"context"
	"errors"
	"math"
	"strings"

	"github.com/google/uuid"
)

type Service struct {
	repository *Repository
}

func NewService(repository *Repository) *Service {
	return &Service{
		repository: repository,
	}
}

func (s *Service) CreatePermission(
	ctx context.Context,
	req CreatePermissionRequest,
) (*CreatePermissionResponse, error) {

	req.PermissionCode = strings.TrimSpace(
		strings.ToUpper(req.PermissionCode),
	)

	req.PermissionName = strings.TrimSpace(
		req.PermissionName,
	)

	req.ModuleName = strings.TrimSpace(
		strings.ToUpper(req.ModuleName),
	)

	req.ActionName = strings.TrimSpace(
		strings.ToUpper(req.ActionName),
	)

	req.RiskLevel = strings.TrimSpace(
		strings.ToUpper(req.RiskLevel),
	)

	req.Status = strings.TrimSpace(
		strings.ToUpper(req.Status),
	)

	if req.PermissionCode == "" {
		return nil, errors.New(
			"permission code is required",
		)
	}

	if req.PermissionName == "" {
		return nil, errors.New(
			"permission name is required",
		)
	}

	if req.ModuleName == "" {
		return nil, errors.New(
			"module name is required",
		)
	}

	if req.ActionName == "" {
		return nil, errors.New(
			"action name is required",
		)
	}

	switch req.RiskLevel {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		return nil, errors.New(
			"invalid risk level",
		)
	}

	if req.Status == "" {
		req.Status = "ACTIVE"
	}

	switch req.Status {
	case "ACTIVE", "INACTIVE":
	default:
		return nil, errors.New(
			"invalid status",
		)
	}

	if req.Description != nil {
		description := strings.TrimSpace(
			*req.Description,
		)

		req.Description = &description
	}

	return s.repository.CreatePermission(
		ctx,
		req,
	)
}

func (s *Service) ListPermissions(
	ctx context.Context,
	req ListPermissionsRequest,
) (*ListPermissionsResponse, error) {

	if req.Page <= 0 {
		req.Page = 1
	}

	if req.PageSize <= 0 {
		req.PageSize = 10
	}

	if req.PageSize > 100 {
		req.PageSize = 100
	}

	req.Search = strings.TrimSpace(
		req.Search,
	)

	req.Module = strings.TrimSpace(
		strings.ToUpper(req.Module),
	)

	req.Status = strings.TrimSpace(
		strings.ToUpper(req.Status),
	)

	if req.Status != "" {
		switch req.Status {
		case "ACTIVE", "INACTIVE":
		default:
			return nil, errors.New(
				"invalid status",
			)
		}
	}

	result, err := s.repository.ListPermissions(
		ctx,
		req,
	)
	if err != nil {
		return nil, err
	}

	result.TotalPages = int(
		math.Ceil(
			float64(result.Total) /
				float64(req.PageSize),
		),
	)

	return result, nil
}

func (s *Service) GetPermissionByID(
	ctx context.Context,
	permissionID uuid.UUID,
) (*GetPermissionResponse, error) {

	return s.repository.GetPermissionByID(
		ctx,
		permissionID,
	)
}

func (s *Service) UpdatePermission(
	ctx context.Context,
	permissionID uuid.UUID,
	req UpdatePermissionRequest,
) (*GetPermissionResponse, error) {

	if req.PermissionName != nil {
		permissionName := strings.TrimSpace(*req.PermissionName)

		if permissionName == "" {
			return nil, errors.New(
				"permission name cannot be empty",
			)
		}

		*req.PermissionName = permissionName
	}

	if req.ModuleName != nil {
		moduleName := strings.TrimSpace(
			strings.ToUpper(*req.ModuleName),
		)

		if moduleName == "" {
			return nil, errors.New(
				"module name cannot be empty",
			)
		}

		*req.ModuleName = moduleName
	}

	if req.ActionName != nil {
		actionName := strings.TrimSpace(
			strings.ToUpper(*req.ActionName),
		)

		if actionName == "" {
			return nil, errors.New(
				"action name cannot be empty",
			)
		}

		*req.ActionName = actionName
	}

	if req.Description != nil {
		description := strings.TrimSpace(
			*req.Description,
		)

		*req.Description = description
	}

	if req.RiskLevel != nil {
		riskLevel := strings.TrimSpace(
			strings.ToUpper(*req.RiskLevel),
		)

		switch riskLevel {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		default:
			return nil, errors.New(
				"invalid risk level",
			)
		}

		*req.RiskLevel = riskLevel
	}

	if req.Status != nil {
		status := strings.TrimSpace(
			strings.ToUpper(*req.Status),
		)

		switch status {
		case "ACTIVE", "INACTIVE":
		default:
			return nil, errors.New(
				"invalid status",
			)
		}

		*req.Status = status
	}

	if req.PermissionName == nil &&
		req.ModuleName == nil &&
		req.ActionName == nil &&
		req.Description == nil &&
		req.RiskLevel == nil &&
		req.Status == nil {

		return nil, errors.New(
			"at least one field must be provided",
		)
	}

	return s.repository.UpdatePermission(
		ctx,
		permissionID,
		req,
	)
}

func (s *Service) DeletePermission(
	ctx context.Context,
	permissionID uuid.UUID,
) error {

	return s.repository.DeletePermission(
		ctx,
		permissionID,
	)
}
