package userrole

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

func (s *Service) AssignRoles(
	ctx context.Context,
	userID uuid.UUID,
	grantedBy *uuid.UUID,
	req AssignRolesRequest,
) (*AssignRolesResponse, error) {

	if len(req.RoleIDs) == 0 {
		return nil, errors.New(
			"at least one role must be selected",
		)
	}

	unique := make(map[uuid.UUID]struct{})
	roleIDs := make([]uuid.UUID, 0)

	for _, roleID := range req.RoleIDs {

		if roleID == uuid.Nil {
			return nil, errors.New(
				"invalid role id",
			)
		}

		if _, ok := unique[roleID]; ok {
			continue
		}

		unique[roleID] = struct{}{}
		roleIDs = append(
			roleIDs,
			roleID,
		)
	}

	req.RoleIDs = roleIDs

	return s.repository.AssignRoles(
		ctx,
		userID,
		grantedBy,
		req,
	)
}

func (s *Service) ListUserRoles(
	ctx context.Context,
	userID uuid.UUID,
) (*ListUserRolesResponse, error) {

	if userID == uuid.Nil {
		return nil, errors.New("invalid user id")
	}

	return s.repository.ListUserRoles(
		ctx,
		userID,
	)
}

func (s *Service) RemoveRole(
	ctx context.Context,
	userID uuid.UUID,
	roleID uuid.UUID,
) error {

	return s.repository.RemoveRole(
		ctx,
		userID,
		roleID,
	)
}

func (s *Service) ReplaceRoles(
	ctx context.Context,
	userID uuid.UUID,
	grantedBy *uuid.UUID,
	req ReplaceRolesRequest,
) (*AssignRolesResponse, error) {

	if len(req.RoleIDs) == 0 {
		return nil, errors.New(
			"at least one role must be selected",
		)
	}

	unique := make(map[uuid.UUID]struct{})
	roleIDs := make([]uuid.UUID, 0)

	for _, roleID := range req.RoleIDs {

		if roleID == uuid.Nil {
			return nil, errors.New(
				"invalid role id",
			)
		}

		if _, ok := unique[roleID]; ok {
			continue
		}

		unique[roleID] = struct{}{}
		roleIDs = append(
			roleIDs,
			roleID,
		)
	}

	req.RoleIDs = roleIDs

	return s.repository.ReplaceRoles(
		ctx,
		userID,
		grantedBy,
		req,
	)
}
