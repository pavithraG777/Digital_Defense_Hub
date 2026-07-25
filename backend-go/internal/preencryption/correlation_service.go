package preencryption

import (
	"context"
	"errors"
	"time"
)

// RefreshPendingDetectionCorrelations resolves Threat and Incident
// relationships that may have been created asynchronously after the
// pre-encryption detection was persisted.
func (s *Service) RefreshPendingDetectionCorrelations(
	ctx context.Context,
	batchSize int,
) (int64, error) {
	if s == nil || s.repository == nil {
		return 0, errors.New(
			"pre-encryption detection service is unavailable",
		)
	}

	return s.repository.
		RefreshPendingDetectionCorrelations(
			ctx,
			batchSize,
			time.Now().UTC(),
		)
}
