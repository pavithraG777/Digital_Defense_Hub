package router

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/config"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/preencryption"
)

// initializePreEncryptionModule creates the repository,
// Python engine client, detection service, API handler
// and asynchronous file-event analysis worker.
func initializePreEncryptionModule(
	databasePool *pgxpool.Pool,
	cfg *config.Config,
	logger *zap.Logger,
) (
	*preencryption.Worker,
	*preencryption.Handler,
	error,
) {
	if databasePool == nil {
		return nil, nil, errors.New(
			"database pool is required for pre-encryption module",
		)
	}

	if cfg == nil {
		return nil, nil, errors.New(
			"configuration is required for pre-encryption module",
		)
	}

	if !cfg.PreEncryption.Enabled {
		return nil, nil, nil
	}

	engineClient, err :=
		preencryption.NewEngineClient(
			cfg.AIRisk.EngineURL,
			cfg.AIRisk.ServiceToken,
			cfg.AIRisk.Timeout,
		)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize pre-encryption engine client: %w",
			err,
		)
	}

	repository := preencryption.NewRepository(
		databasePool,
	)

	service, err := preencryption.NewService(
		repository,
		engineClient,
		preencryption.FeaturePolicy{},
		cfg.PreEncryption.WindowDuration,
		cfg.PreEncryption.MinimumScore,
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize pre-encryption detection service: %w",
			err,
		)
	}

	handler := preencryption.NewHandler(
		service,
	)

	worker, err := preencryption.NewWorker(
		service,
		logger,
		cfg.PreEncryption.WorkerCount,
		cfg.PreEncryption.QueueCapacity,
		cfg.PreEncryption.AnalysisTimeout,
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize pre-encryption detection worker: %w",
			err,
		)
	}

	return worker, handler, nil
}
