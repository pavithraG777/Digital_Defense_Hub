package role

import (
	"context"
	"errors"
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

func (s *Service) CreateRole(
	ctx context.Context,
	organizationID uuid.UUID,
	req CreateRoleRequest,
) (*CreateRoleResponse, error) {

	req.RoleCode = strings.TrimSpace(strings.ToUpper(req.RoleCode))
	req.RoleName = strings.TrimSpace(req.RoleName)

	if req.Description != nil {
		description := strings.TrimSpace(*req.Description)
		req.Description = &description
	}

	req.RoleScope = strings.TrimSpace(strings.ToUpper(req.RoleScope))

	if req.RoleCode == "" {
		return nil, errors.New("role code is required")
	}

	if req.RoleName == "" {
		return nil, errors.New("role name is required")
	}

	if req.RoleScope == "" {
		req.RoleScope = "ORGANIZATION"
	}

	switch req.RoleScope {
	case "GLOBAL", "ORGANIZATION", "DEPARTMENT":
	default:
		return nil, errors.New("invalid role scope")
	}

	return s.repository.CreateRole(
		ctx,
		organizationID,
		req,
	)
}

func (s *Service) ListRoles(
	ctx context.Context,
	organizationID uuid.UUID,
	req ListRolesRequest,
) (*ListRolesResponse, error) {

	if req.Page <= 0 {
		req.Page = 1
	}

	if req.PageSize <= 0 {
		req.PageSize = 10
	}

	if req.PageSize > 100 {
		req.PageSize = 100
	}

	req.Search = strings.TrimSpace(req.Search)
	req.Status = strings.TrimSpace(strings.ToUpper(req.Status))

	roles, totalCount, err := s.repository.ListRoles(
		ctx,
		organizationID,
		req,
	)
	if err != nil {
		return nil, err
	}

	totalPages := int((totalCount + int64(req.PageSize) - 1) / int64(req.PageSize))

	return &ListRolesResponse{
		Roles:      roles,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalCount: totalCount,
		TotalPages: totalPages,
	}, nil
}

func (s *Service) GetRoleByID(
	ctx context.Context,
	organizationID uuid.UUID,
	roleID uuid.UUID,
) (*GetRoleResponse, error) {
	return s.repository.GetRoleByID(
		ctx,
		organizationID,
		roleID,
	)
}
func (s *Service) UpdateRole(
	ctx context.Context,
	organizationID uuid.UUID,
	roleID uuid.UUID,
	req UpdateRoleRequest,
) (*GetRoleResponse, error) {

	if req.RoleName != nil {
		roleName := strings.TrimSpace(*req.RoleName)

		if roleName == "" {
			return nil, errors.New("role name cannot be empty")
		}

		*req.RoleName = roleName
	}

	if req.Description != nil {
		description := strings.TrimSpace(*req.Description)
		*req.Description = description
	}

	if req.RoleScope != nil {
		roleScope := strings.TrimSpace(strings.ToUpper(*req.RoleScope))

		switch roleScope {
		case "GLOBAL", "ORGANIZATION", "DEPARTMENT":
		default:
			return nil, errors.New("invalid role scope")
		}

		*req.RoleScope = roleScope
	}

	if req.Status != nil {
		status := strings.TrimSpace(strings.ToUpper(*req.Status))

		switch status {
		case "ACTIVE", "INACTIVE":
		default:
			return nil, errors.New("invalid status")
		}

		*req.Status = status
	}

	if req.RoleName == nil &&
		req.Description == nil &&
		req.RoleScope == nil &&
		req.DepartmentID == nil &&
		req.PriorityLevel == nil &&
		req.Status == nil {

		return nil, errors.New("at least one field must be provided")
	}

	return s.repository.UpdateRole(
		ctx,
		organizationID,
		roleID,
		req,
	)
}

func (s *Service) DeleteRole(
	ctx context.Context,
	organizationID uuid.UUID,
	roleID uuid.UUID,
) error {
	return s.repository.DeleteRole(
		ctx,
		organizationID,
		roleID,
	)
}
