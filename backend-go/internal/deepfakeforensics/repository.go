package deepfakeforensics

import (
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRepositoryUnavailable = errors.New(
		"deepfake forensics repository is unavailable",
	)

	ErrInvalidRepositoryInput = errors.New(
		"invalid deepfake forensics repository input",
	)

	ErrMediaAssetNotFound = errors.New(
		"media analysis asset not found",
	)

	ErrMediaAssetConflict = errors.New(
		"media analysis asset already exists",
	)

	ErrAnalysisJobNotFound = errors.New(
		"AI analysis job not found",
	)

	ErrAnalysisJobConflict = errors.New(
		"AI analysis job is in a conflicting state",
	)

	ErrAnalysisModelNotFound = errors.New(
		"compatible AI analysis model not found",
	)

	ErrAnalysisResultNotFound = errors.New(
		"media analysis result not found",
	)
)

// Repository provides organization-scoped persistence for
// media assets, AI analysis jobs, registered models and
// multimodal forensic results.
type Repository struct {
	databasePool *pgxpool.Pool
}

// NewRepository creates the persistence boundary used by
// the deepfake and multimodal forensic module.
func NewRepository(
	databasePool *pgxpool.Pool,
) (*Repository, error) {
	if databasePool == nil {
		return nil, ErrRepositoryUnavailable
	}

	return &Repository{
		databasePool: databasePool,
	}, nil
}

// IsAvailable reports whether the repository has a usable
// PostgreSQL connection pool.
func (r *Repository) IsAvailable() bool {
	return r != nil &&
		r.databasePool != nil
}

func (r *Repository) validateAvailable() error {
	if !r.IsAvailable() {
		return ErrRepositoryUnavailable
	}

	return nil
}
