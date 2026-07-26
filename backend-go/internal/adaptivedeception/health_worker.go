package adaptivedeception

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	defaultHealthWorkerPollInterval = 1 * time.Minute
	defaultHealthWorkerCheckTimeout = 30 * time.Second
)

// HealthWorker periodically checks deployed canary files
// whose next health-check time has arrived.
type HealthWorker struct {
	repository *Repository
	service    *HealthService
	logger     *zap.Logger

	pollInterval time.Duration
	checkTimeout time.Duration
	batchSize    int

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewHealthWorker(
	repository *Repository,
	service *HealthService,
	logger *zap.Logger,
	pollInterval time.Duration,
	checkTimeout time.Duration,
	batchSize int,
) (*HealthWorker, error) {
	if repository == nil {
		return nil, errors.New(
			"adaptive deception repository is required",
		)
	}

	if service == nil {
		return nil, errors.New(
			"canary health service is required",
		)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	if pollInterval <= 0 {
		pollInterval =
			defaultHealthWorkerPollInterval
	}

	if checkTimeout <= 0 {
		checkTimeout =
			defaultHealthWorkerCheckTimeout
	}

	if batchSize <= 0 {
		batchSize =
			defaultHealthTargetBatchSize
	}

	if batchSize >
		maximumHealthTargetBatchSize {
		batchSize =
			maximumHealthTargetBatchSize
	}

	return &HealthWorker{
		repository: repository,
		service:    service,
		logger:     logger,

		pollInterval: pollInterval,
		checkTimeout: checkTimeout,
		batchSize:    batchSize,
	}, nil
}

func (w *HealthWorker) Start(
	ctx context.Context,
) error {
	if w == nil ||
		w.repository == nil ||
		w.service == nil {
		return errors.New(
			"canary health worker is unavailable",
		)
	}

	if ctx == nil {
		return errors.New(
			"canary health worker context is required",
		)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return nil
	}

	workerContext, cancel :=
		context.WithCancel(ctx)

	w.cancel = cancel
	w.done = make(chan struct{})
	w.running = true

	go w.run(
		workerContext,
		w.done,
	)

	w.logger.Info(
		"Adaptive deception canary health worker started",
		zap.Duration(
			"poll_interval",
			w.pollInterval,
		),
		zap.Duration(
			"check_timeout",
			w.checkTimeout,
		),
		zap.Int(
			"batch_size",
			w.batchSize,
		),
	)

	return nil
}

func (w *HealthWorker) Stop(
	ctx context.Context,
) error {
	if w == nil {
		return nil
	}

	w.mu.Lock()

	if !w.running {
		w.mu.Unlock()
		return nil
	}

	cancel := w.cancel
	done := w.done

	w.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	select {
	case <-done:
		return nil

	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *HealthWorker) run(
	ctx context.Context,
	done chan struct{},
) {
	defer func() {
		w.mu.Lock()
		w.running = false
		w.cancel = nil
		w.mu.Unlock()

		close(done)

		w.logger.Info(
			"Adaptive deception canary health worker stopped",
		)
	}()

	w.processDueHealthChecks(ctx)

	ticker := time.NewTicker(
		w.pollInterval,
	)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			w.processDueHealthChecks(ctx)
		}
	}
}

func (w *HealthWorker) processDueHealthChecks(
	ctx context.Context,
) {
	targets, err :=
		w.repository.ListDueHealthCheckTargets(
			ctx,
			w.batchSize,
		)
	if err != nil {
		if ctx.Err() != nil {
			return
		}

		w.logger.Error(
			"Failed to load due canary health targets",
			zap.Error(err),
		)

		return
	}

	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}

		checkContext, cancelCheck :=
			context.WithTimeout(
				ctx,
				w.checkTimeout,
			)

		healthCheck, checkErr :=
			w.service.CheckCanaryHealth(
				checkContext,
				target.OrganizationID,
				target.CanaryFileID,
				HealthCheckTypeScheduled,
			)

		cancelCheck()

		if checkErr != nil {
			if ctx.Err() != nil {
				return
			}

			w.logger.Error(
				"Scheduled canary health check failed",
				zap.String(
					"organization_id",
					target.OrganizationID.String(),
				),
				zap.String(
					"canary_file_id",
					target.CanaryFileID.String(),
				),
				zap.String(
					"canary_code",
					target.CanaryCode,
				),
				zap.Error(checkErr),
			)

			continue
		}

		logFields := []zap.Field{
			zap.String(
				"organization_id",
				target.OrganizationID.String(),
			),
			zap.String(
				"canary_file_id",
				target.CanaryFileID.String(),
			),
			zap.String(
				"canary_code",
				target.CanaryCode,
			),
			zap.String(
				"health_status",
				healthCheck.HealthStatus,
			),
			zap.Float64(
				"health_score",
				healthCheck.HealthScore,
			),
		}

		if healthCheck.IsHealthy {
			w.logger.Debug(
				"Scheduled canary health check completed",
				logFields...,
			)

			continue
		}

		w.logger.Warn(
			"Canary health anomaly detected",
			logFields...,
		)
	}
}
