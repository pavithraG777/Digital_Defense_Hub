package adaptivedeception

import (
	"context"
	"errors"
	"fmt"
)

// FingerprintService coordinates deterministic fingerprint
// generation, behavioural scoring and atomic persistence.
type FingerprintService struct {
	repository *Repository
}

func NewFingerprintService(
	repository *Repository,
) (*FingerprintService, error) {
	if repository == nil {
		return nil, errors.New(
			"adaptive deception repository is required",
		)
	}

	return &FingerprintService{
		repository: repository,
	}, nil
}

// RecordInteraction builds and stores a canary interaction
// fingerprint. Repeated patterns increment occurrence_count.
func (s *FingerprintService) RecordInteraction(
	ctx context.Context,
	input CanaryInteractionInput,
) (*CanaryInteractionFingerprint, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"canary fingerprint service is unavailable",
		)
	}

	fingerprint, err :=
		BuildCanaryInteractionFingerprint(
			input,
		)
	if err != nil {
		return nil, err
	}

	if err = ScoreCanaryInteractionFingerprint(
		fingerprint,
	); err != nil {
		return nil, fmt.Errorf(
			"score canary interaction fingerprint: %w",
			err,
		)
	}

	if err = validateFingerprintScores(
		fingerprint,
	); err != nil {
		return nil, fmt.Errorf(
			"validate canary interaction fingerprint: %w",
			err,
		)
	}

	persistedFingerprint, err :=
		s.repository.
			UpsertCanaryInteractionFingerprint(
				ctx,
				fingerprint,
			)
	if err != nil {
		return nil, fmt.Errorf(
			"persist canary interaction fingerprint: %w",
			err,
		)
	}

	return persistedFingerprint, nil
}
