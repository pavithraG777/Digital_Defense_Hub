package router

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	honeytoken "github.com/pavithraG777/cyber-security-platform/backend/internal/HoneyToken"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/adaptivedeception"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
)

func initializeAdaptiveDeceptionModule(
	databasePool *pgxpool.Pool,
	cfg *config.Config,
	logger *zap.Logger,
	fileMonitorService *honeytoken.FileMonitorService,
) (
	*adaptivedeception.HealthWorker,
	*adaptivedeception.FingerprintWorker,
	*adaptivedeception.HealthHandler,
	*adaptivedeception.RotationHandler,
	*adaptivedeception.FingerprintHandler,
	error,
) {
	if databasePool == nil {
		return nil, nil, nil, nil, nil, errors.New(
			"database pool is required for adaptive deception module",
		)
	}

	if cfg == nil {
		return nil, nil, nil, nil, nil, errors.New(
			"application configuration is required for adaptive deception module",
		)
	}

	if !cfg.AdaptiveDeception.Enabled {
		return nil, nil, nil, nil, nil, nil
	}

	if fileMonitorService == nil {
		return nil, nil, nil, nil, nil, errors.New(
			"file monitor service is required for adaptive deception module",
		)
	}

	repository :=
		adaptivedeception.NewRepository(
			databasePool,
		)

	healthService, err :=
		adaptivedeception.NewHealthService(
			repository,
			cfg.AdaptiveDeception.
				HealthCheckInterval,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"initialize adaptive deception health service: %w",
			err,
		)
	}

	healthWorker, err :=
		adaptivedeception.NewHealthWorker(
			repository,
			healthService,
			logger,
			cfg.AdaptiveDeception.
				WorkerPollInterval,
			cfg.AdaptiveDeception.
				CheckTimeout,
			cfg.AdaptiveDeception.
				BatchSize,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"initialize adaptive deception health worker: %w",
			err,
		)
	}

	fingerprintService, err :=
		adaptivedeception.NewFingerprintService(
			repository,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"initialize canary fingerprint service: %w",
			err,
		)
	}

	fingerprintQueryService, err :=
		adaptivedeception.NewFingerprintQueryService(
			repository,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"initialize canary fingerprint query service: %w",
			err,
		)
	}

	fingerprintWorker, err :=
		adaptivedeception.NewFingerprintWorker(
			repository,
			fingerprintService,
			logger,
			0,
			0,
			cfg.AdaptiveDeception.
				CheckTimeout,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"initialize canary fingerprint worker: %w",
			err,
		)
	}

	if err = fileMonitorService.
		SetFingerprintWorker(
			fingerprintWorker,
		); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"connect File Event Service to canary fingerprint worker: %w",
			err,
		)
	}

	canaryGenerator, err :=
		honeytoken.NewCanaryGenerator(
			cfg.Storage.CanaryStoragePath,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"initialize adaptive canary generator: %w",
			err,
		)
	}

	rotationFileManager, err :=
		adaptivedeception.NewRotationFileManager(
			cfg.Storage.CanaryDeploymentRoot,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"initialize canary rotation file manager: %w",
			err,
		)
	}

	rotationService, err :=
		adaptivedeception.NewRotationService(
			repository,
			canaryGenerator,
			rotationFileManager,
			healthService,
			fileMonitorService,
		)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf(
			"initialize adaptive canary rotation service: %w",
			err,
		)
	}

	healthHandler :=
		adaptivedeception.NewHealthHandler(
			healthService,
		)

	rotationHandler :=
		adaptivedeception.NewRotationHandler(
			rotationService,
		)

	fingerprintHandler :=
		adaptivedeception.NewFingerprintHandler(
			fingerprintQueryService,
		)

	return healthWorker,
		fingerprintWorker,
		healthHandler,
		rotationHandler,
		fingerprintHandler,
		nil
}
