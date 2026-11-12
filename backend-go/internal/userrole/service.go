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
	organizationID uuid.UUID,
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
		organizationID,
		userID,
		grantedBy,
		req,
	)
}

func (s *Service) BulkAssignRoles(ctx context.Context, organizationID uuid.UUID, grantedBy *uuid.UUID, req BulkAssignRolesRequest) (*BulkAssignRolesResponse, error) {
	if len(req.UserIDs) == 0 || len(req.RoleIDs) == 0 {
		return nil, errors.New("at least one user and role are required")
	}
	users := make([]uuid.UUID, 0, len(req.UserIDs))
	seenUsers := map[uuid.UUID]bool{}
	for _, id := range req.UserIDs {
		if id == uuid.Nil {
			return nil, errors.New("invalid user ID")
		}
		if !seenUsers[id] {
			seenUsers[id] = true
			users = append(users, id)
		}
	}
	roles := make([]uuid.UUID, 0, len(req.RoleIDs))
	seenRoles := map[uuid.UUID]bool{}
	for _, id := range req.RoleIDs {
		if id == uuid.Nil {
			return nil, errors.New("invalid role ID")
		}
		if !seenRoles[id] {
			seenRoles[id] = true
			roles = append(roles, id)
		}
	}
	req.UserIDs, req.RoleIDs = users, roles
	return s.repository.BulkAssignRoles(ctx, organizationID, grantedBy, req)
}

func (s *Service) ListUserRoles(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
) (*ListUserRolesResponse, error) {

	if userID == uuid.Nil {
		return nil, errors.New("invalid user id")
	}

	return s.repository.ListUserRoles(
		ctx,
		organizationID,
		userID,
	)
}

func (s *Service) RemoveRole(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	roleID uuid.UUID,
) error {

	return s.repository.RemoveRole(
		ctx,
		organizationID,
		userID,
		roleID,
	)
}

func (s *Service) ReplaceRoles(
	ctx context.Context,
	organizationID uuid.UUID,
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
		organizationID,
		userID,
		grantedBy,
		req,
	)
}
