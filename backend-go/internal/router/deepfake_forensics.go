package router

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/deepfakeforensics"
)

// initializeDeepfakeForensicsModule wires the durable Go
// orchestration layer to the authenticated offline Python
// media-analysis engine.
func initializeDeepfakeForensicsModule(
	databasePool *pgxpool.Pool,
	cfg *config.Config,
	logger *zap.Logger,
) (
	*deepfakeforensics.Handler,
	*deepfakeforensics.AnalysisWorker,
	error,
) {
	if cfg == nil {
		return nil, nil, errors.New(
			"application configuration is required",
		)
	}

	moduleConfig := cfg.DeepfakeForensics
	if !moduleConfig.Enabled {
		return nil, nil, nil
	}

	if databasePool == nil {
		return nil, nil, errors.New(
			"database pool is required for deepfake forensics",
		)
	}

	repository, err :=
		deepfakeforensics.NewRepository(
			databasePool,
		)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize deepfake forensics repository: %w",
			err,
		)
	}

	fileManager, err :=
		deepfakeforensics.NewAssetFileManager(
			moduleConfig.StoragePath,
			moduleConfig.MaximumUploadBytes,
		)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize deepfake forensics storage: %w",
			err,
		)
	}

	assetService, err :=
		deepfakeforensics.NewAssetService(
			repository,
			fileManager,
		)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize deepfake forensics asset service: %w",
			err,
		)
	}

	analysisService, err :=
		deepfakeforensics.NewAnalysisService(
			repository,
		)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize deepfake forensics analysis service: %w",
			err,
		)
	}

	queryService, err :=
		deepfakeforensics.NewQueryService(
			repository,
		)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize deepfake forensics query service: %w",
			err,
		)
	}

	handler, err := deepfakeforensics.NewHandler(
		assetService,
		analysisService,
		queryService,
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize deepfake forensics handler: %w",
			err,
		)
	}

	engineClient, err :=
		deepfakeforensics.NewEngineClient(
			moduleConfig.EngineURL,
			moduleConfig.ServiceToken,
			moduleConfig.EngineTimeout,
		)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize deepfake forensics engine client: %w",
			err,
		)
	}

	worker, err :=
		deepfakeforensics.NewAnalysisWorker(
			repository,
			engineClient,
			logger,
			moduleConfig.WorkerCount,
			moduleConfig.PollInterval,
			moduleConfig.AnalysisTimeout,
			moduleConfig.ProcessingNode,
		)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize deepfake forensics worker: %w",
			err,
		)
	}

	return handler, worker, nil
}
