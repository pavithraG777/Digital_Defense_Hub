package notification

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
)

var ErrNotificationWorkerAlreadyStarted = errors.New(
	"notification worker is already started",
)

type WorkerConfig struct {
	WorkerCount           int
	BatchSize             int
	PollInterval          time.Duration
	DeliveryTimeout       time.Duration
	MaintenanceInterval   time.Duration
	StaleProcessingPeriod time.Duration
}

func DefaultWorkerConfig() WorkerConfig {
	return WorkerConfig{
		WorkerCount:           4,
		BatchSize:             20,
		PollInterval:          2 * time.Second,
		DeliveryTimeout:       30 * time.Second,
		MaintenanceInterval:   time.Minute,
		StaleProcessingPeriod: 5 * time.Minute,
	}
}

type Worker struct {
	repository *Repository
	dispatcher *Dispatcher
	logger     *zap.Logger
	config     WorkerConfig

	stateMutex sync.Mutex
	running    bool
	cancel     context.CancelFunc
	done       chan struct{}
	waitGroup  sync.WaitGroup
}

func NewWorker(
	repository *Repository,
	dispatcher *Dispatcher,
	logger *zap.Logger,
	config WorkerConfig,
) (*Worker, error) {
	if repository == nil {
		return nil, errors.New(
			"notification repository is required",
		)
	}

	if dispatcher == nil {
		return nil, errors.New(
			"notification dispatcher is required",
		)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	config = normalizeWorkerConfig(config)

	return &Worker{
		repository: repository,
		dispatcher: dispatcher,
		logger:     logger,
		config:     config,
	}, nil
}

func (w *Worker) Start(
	parentContext context.Context,
) error {
	if w == nil {
		return errors.New(
			"notification worker is unavailable",
		)
	}

	if parentContext == nil {
		parentContext = context.Background()
	}

	w.stateMutex.Lock()

	if w.running {
		w.stateMutex.Unlock()

		return ErrNotificationWorkerAlreadyStarted
	}

	workerContext, cancel :=
		context.WithCancel(parentContext)

	w.running = true
	w.cancel = cancel
	w.done = make(chan struct{})

	for workerIndex := 1; workerIndex <= w.config.WorkerCount; workerIndex++ {
		w.waitGroup.Add(1)

		go w.runWorker(
			workerContext,
			workerIndex,
		)
	}

	w.waitGroup.Add(1)

	go w.runMaintenanceLoop(
		workerContext,
	)

	done := w.done

	go func() {
		w.waitGroup.Wait()
		close(done)
	}()

	w.stateMutex.Unlock()

	w.logger.Info(
		"Notification delivery worker started",
		zap.Int(
			"worker_count",
			w.config.WorkerCount,
		),
		zap.Int(
			"batch_size",
			w.config.BatchSize,
		),
		zap.Duration(
			"poll_interval",
			w.config.PollInterval,
		),
	)

	return nil
}

func (w *Worker) Stop(
	ctx context.Context,
) error {
	if w == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	w.stateMutex.Lock()

	if !w.running {
		w.stateMutex.Unlock()

		return nil
	}

	cancel := w.cancel
	done := w.done

	w.stateMutex.Unlock()

	if cancel != nil {
		cancel()
	}

	select {
	case <-done:
		w.stateMutex.Lock()
		w.running = false
		w.cancel = nil
		w.done = nil
		w.stateMutex.Unlock()

		w.logger.Info(
			"Notification delivery worker stopped",
		)

		return nil

	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Worker) Running() bool {
	if w == nil {
		return false
	}

	w.stateMutex.Lock()
	defer w.stateMutex.Unlock()

	return w.running
}

func (w *Worker) runWorker(
	ctx context.Context,
	workerIndex int,
) {
	defer w.waitGroup.Done()

	pollTimer := time.NewTimer(0)

	defer func() {
		if !pollTimer.Stop() {
			select {
			case <-pollTimer.C:
			default:
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return

		case <-pollTimer.C:
		}

		processedCount, err :=
			w.processDeliveryBatch(
				ctx,
				workerIndex,
			)

		if err != nil &&
			!errors.Is(
				err,
				context.Canceled,
			) {
			w.logger.Error(
				"Notification delivery batch failed",
				zap.Int(
					"worker_index",
					workerIndex,
				),
				zap.Error(err),
			)
		}

		nextPollDelay :=
			w.config.PollInterval

		if err == nil &&
			processedCount >=
				w.config.BatchSize {
			nextPollDelay = 10 * time.Millisecond
		}

		pollTimer.Reset(nextPollDelay)
	}
}

func (w *Worker) processDeliveryBatch(
	ctx context.Context,
	workerIndex int,
) (int, error) {
	claimedAt := time.Now().UTC()

	deliveries, err :=
		w.repository.ClaimPendingDeliveries(
			ctx,
			w.config.BatchSize,
			claimedAt,
		)
	if err != nil {
		return 0, err
	}

	for index := range deliveries {
		if err = ctx.Err(); err != nil {
			return index, err
		}

		delivery := deliveries[index]

		deliveryContext, cancel :=
			context.WithTimeout(
				ctx,
				w.config.DeliveryTimeout,
			)

		result, dispatchErr :=
			w.dispatcher.Dispatch(
				deliveryContext,
				&delivery,
			)

		cancel()

		if dispatchErr != nil {
			logFields := []zap.Field{
				zap.Int(
					"worker_index",
					workerIndex,
				),
				zap.String(
					"delivery_id",
					delivery.ID.String(),
				),
				zap.String(
					"notification_id",
					delivery.NotificationID.String(),
				),
				zap.String(
					"organization_id",
					delivery.OrganizationID.String(),
				),
				zap.String(
					"channel",
					delivery.Channel,
				),
				zap.Int(
					"attempt_count",
					delivery.AttemptCount,
				),
				zap.Error(dispatchErr),
			}

			if result != nil {
				logFields = append(
					logFields,
					zap.String(
						"delivery_status",
						result.DeliveryStatus,
					),
				)
			}

			w.logger.Warn(
				"Notification delivery attempt failed",
				logFields...,
			)

			continue
		}

		if result != nil {
			w.logger.Info(
				"Notification delivery processed",
				zap.Int(
					"worker_index",
					workerIndex,
				),
				zap.String(
					"delivery_id",
					result.ID.String(),
				),
				zap.String(
					"notification_id",
					result.NotificationID.String(),
				),
				zap.String(
					"channel",
					result.Channel,
				),
				zap.String(
					"delivery_status",
					result.DeliveryStatus,
				),
			)
		}
	}

	return len(deliveries), nil
}

func (w *Worker) runMaintenanceLoop(
	ctx context.Context,
) {
	defer w.waitGroup.Done()

	w.runMaintenance(ctx)

	ticker := time.NewTicker(
		w.config.MaintenanceInterval,
	)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			w.runMaintenance(ctx)
		}
	}
}

func (w *Worker) runMaintenance(
	ctx context.Context,
) {
	if err := ctx.Err(); err != nil {
		return
	}

	now := time.Now().UTC()

	staleBefore := now.Add(
		-w.config.StaleProcessingPeriod,
	)

	requeuedCount, err :=
		w.repository.RequeueStaleProcessingDeliveries(
			ctx,
			staleBefore,
			now,
		)
	if err != nil {
		if !errors.Is(
			err,
			context.Canceled,
		) {
			w.logger.Error(
				"Failed to recover stale notification deliveries",
				zap.Error(err),
			)
		}
	} else if requeuedCount > 0 {
		w.logger.Warn(
			"Recovered stale notification deliveries",
			zap.Int64(
				"delivery_count",
				requeuedCount,
			),
		)
	}

	expiredCount, err :=
		w.repository.ExpireNotifications(
			ctx,
			now,
		)
	if err != nil {
		if !errors.Is(
			err,
			context.Canceled,
		) {
			w.logger.Error(
				"Failed to expire notifications",
				zap.Error(err),
			)
		}
	} else if expiredCount > 0 {
		w.logger.Info(
			"Expired scheduled notifications",
			zap.Int64(
				"notification_count",
				expiredCount,
			),
		)
	}
}

func normalizeWorkerConfig(
	config WorkerConfig,
) WorkerConfig {
	defaultConfig := DefaultWorkerConfig()

	if config.WorkerCount <= 0 {
		config.WorkerCount =
			defaultConfig.WorkerCount
	}

	if config.WorkerCount > 32 {
		config.WorkerCount = 32
	}

	if config.BatchSize <= 0 {
		config.BatchSize =
			defaultConfig.BatchSize
	}

	if config.BatchSize > 100 {
		config.BatchSize = 100
	}

	if config.PollInterval <= 0 {
		config.PollInterval =
			defaultConfig.PollInterval
	}

	if config.DeliveryTimeout <= 0 {
		config.DeliveryTimeout =
			defaultConfig.DeliveryTimeout
	}

	if config.MaintenanceInterval <= 0 {
		config.MaintenanceInterval =
			defaultConfig.MaintenanceInterval
	}

	if config.StaleProcessingPeriod <= 0 {
		config.StaleProcessingPeriod =
			defaultConfig.StaleProcessingPeriod
	}

	return config
}
