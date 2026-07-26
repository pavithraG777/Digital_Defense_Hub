package adaptivedeception

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

func (s *HealthService) GetCanaryHealthDetails(
	ctx context.Context,
	organizationID uuid.UUID,
	canaryFileID uuid.UUID,
) (*CanaryHealthDetailsResponse, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"canary health service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if canaryFileID == uuid.Nil {
		return nil, errors.New(
			"canary file ID is required",
		)
	}

	canaryFile, err :=
		s.repository.GetCanaryFileSnapshot(
			ctx,
			organizationID,
			canaryFileID,
		)
	if err != nil {
		return nil, err
	}

	latestHealthCheck, err :=
		s.repository.GetLatestHealthCheck(
			ctx,
			organizationID,
			canaryFileID,
		)
	if err != nil {
		return nil, err
	}

	return &CanaryHealthDetailsResponse{
		CanaryFile:        *canaryFile,
		LatestHealthCheck: *latestHealthCheck,
	}, nil
}
