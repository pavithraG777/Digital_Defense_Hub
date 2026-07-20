package rolepermission

import (
	"context"
	"errors"

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

func (s *Service) AssignPermissions(
	ctx context.Context,
	roleID uuid.UUID,
	grantedBy *uuid.UUID,
	req AssignPermissionsRequest,
) (*AssignPermissionsResponse, error) {

	if len(req.PermissionIDs) == 0 {
		return nil, errors.New(
			"at least one permission must be selected",
		)
	}

	unique := make(map[uuid.UUID]struct{})
	permissionIDs := make([]uuid.UUID, 0)

	for _, permissionID := range req.PermissionIDs {

		if permissionID == uuid.Nil {
			return nil, errors.New(
				"invalid permission id",
			)
		}

		if _, ok := unique[permissionID]; ok {
			continue
		}

		unique[permissionID] = struct{}{}
		permissionIDs = append(
			permissionIDs,
			permissionID,
		)
	}

	req.PermissionIDs = permissionIDs

	return s.repository.AssignPermissions(
		ctx,
		roleID,
		grantedBy,
		req,
	)
}

func (s *Service) ListRolePermissions(
	ctx context.Context,
	roleID uuid.UUID,
) (*ListRolePermissionsResponse, error) {

	if roleID == uuid.Nil {
		return nil, errors.New("invalid role id")
	}

	return s.repository.ListRolePermissions(
		ctx,
		roleID,
	)
}

func (s *Service) RemovePermission(
	ctx context.Context,
	roleID uuid.UUID,
	permissionID uuid.UUID,
) error {

	return s.repository.RemovePermission(
		ctx,
		roleID,
		permissionID,
	)
}

func (s *Service) ReplacePermissions(
	ctx context.Context,
	roleID uuid.UUID,
	grantedBy *uuid.UUID,
	req ReplacePermissionsRequest,
) (*AssignPermissionsResponse, error) {

	return s.repository.ReplacePermissions(
		ctx,
		roleID,
		grantedBy,
		req,
	)
}
