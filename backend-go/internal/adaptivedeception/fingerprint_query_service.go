package adaptivedeception

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidCanaryFingerprintQuery = errors.New(
	"invalid canary fingerprint query",
)

type FingerprintQueryService struct {
	repository *Repository
}

func NewFingerprintQueryService(
	repository *Repository,
) (*FingerprintQueryService, error) {
	if repository == nil {
		return nil, errors.New(
			"adaptive deception repository is required",
		)
	}

	return &FingerprintQueryService{
		repository: repository,
	}, nil
}

func (s *FingerprintQueryService) GetFingerprint(
	ctx context.Context,
	organizationID uuid.UUID,
	fingerprintID string,
) (*CanaryInteractionFingerprint, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"canary fingerprint query service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: organization ID is required",
			ErrInvalidCanaryFingerprintQuery,
		)
	}

	parsedFingerprintID, err := uuid.Parse(
		strings.TrimSpace(
			fingerprintID,
		),
	)
	if err != nil ||
		parsedFingerprintID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: fingerprint ID must be a valid UUID",
			ErrInvalidCanaryFingerprintQuery,
		)
	}

	return s.repository.
		GetCanaryInteractionFingerprint(
			ctx,
			organizationID,
			parsedFingerprintID,
		)
}

func (s *FingerprintQueryService) ListFingerprints(
	ctx context.Context,
	organizationID uuid.UUID,
	request ListFingerprintsRequest,
) (*ListFingerprintsResponse, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"canary fingerprint query service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: organization ID is required",
			ErrInvalidCanaryFingerprintQuery,
		)
	}

	var canaryFileID *uuid.UUID

	canaryIDValue :=
		strings.TrimSpace(
			request.CanaryFileID,
		)

	if canaryIDValue != "" {
		parsedCanaryID, err := uuid.Parse(
			canaryIDValue,
		)
		if err != nil ||
			parsedCanaryID == uuid.Nil {
			return nil, fmt.Errorf(
				"%w: canary file ID must be a valid UUID",
				ErrInvalidCanaryFingerprintQuery,
			)
		}

		canaryFileID = &parsedCanaryID
	}

	if request.MinimumBehaviouralScore != nil &&
		(*request.MinimumBehaviouralScore < 0 ||
			*request.MinimumBehaviouralScore > 100) {
		return nil, fmt.Errorf(
			"%w: minimum behavioural score must be between 0 and 100",
			ErrInvalidCanaryFingerprintQuery,
		)
	}

	observedFrom, err :=
		parseFingerprintQueryTime(
			request.ObservedFrom,
			"observed_from",
		)
	if err != nil {
		return nil, err
	}

	observedTo, err :=
		parseFingerprintQueryTime(
			request.ObservedTo,
			"observed_to",
		)
	if err != nil {
		return nil, err
	}

	if observedFrom != nil &&
		observedTo != nil &&
		observedTo.Before(
			*observedFrom,
		) {
		return nil, fmt.Errorf(
			"%w: observed_to cannot precede observed_from",
			ErrInvalidCanaryFingerprintQuery,
		)
	}

	page := request.Page
	if page <= 0 {
		page = 1
	}

	pageSize := request.PageSize
	if pageSize <= 0 {
		pageSize =
			defaultFingerprintPageSize
	}

	if pageSize >
		maximumFingerprintPageSize {
		pageSize =
			maximumFingerprintPageSize
	}

	fingerprints, total, err :=
		s.repository.
			ListCanaryInteractionFingerprints(
				ctx,
				FingerprintListFilter{
					OrganizationID: organizationID,
					CanaryFileID:   canaryFileID,

					EventType: request.EventType,

					IsSuspicious: request.IsSuspicious,

					RansomwareSuspected: request.
						RansomwareSuspected,

					MinimumBehaviouralScore: request.
						MinimumBehaviouralScore,

					ObservedFrom: observedFrom,
					ObservedTo:   observedTo,

					Limit: pageSize,

					Offset: (page - 1) *
						pageSize,
				},
			)
	if err != nil {
		return nil, err
	}

	if fingerprints == nil {
		fingerprints = make(
			[]CanaryInteractionFingerprint,
			0,
		)
	}

	totalPages := 0

	if total > 0 {
		totalPages = int(
			(total +
				int64(pageSize) -
				1) /
				int64(pageSize),
		)
	}

	return &ListFingerprintsResponse{
		Items: fingerprints,

		Total: total,

		Page:     page,
		PageSize: pageSize,

		TotalPages: totalPages,
	}, nil
}

func parseFingerprintQueryTime(
	value string,
	fieldName string,
) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	parsedValue, err := time.Parse(
		time.RFC3339Nano,
		value,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %s must use RFC3339 format",
			ErrInvalidCanaryFingerprintQuery,
			fieldName,
		)
	}

	parsedValue = parsedValue.UTC()

	return &parsedValue, nil
}
