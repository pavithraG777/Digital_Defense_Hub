package preencryption

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	defaultWorkerCount   = 2
	defaultQueueCapacity = 256

	defaultAnalysisTimeout = 30 * time.Second

	defaultCorrelationMaintenanceInterval = 5 * time.Second

	defaultCorrelationMaintenanceTimeout = 10 * time.Second
)

type analysisJob struct {
	OrganizationID uuid.UUID
	FileEventID    uuid.UUID
}

type Worker struct {
	service *Service
	logger  *zap.Logger

	workerCount int

	analysisTimeout time.Duration

	queue chan analysisJob

	stateMu sync.RWMutex
	started bool
	cancel  context.CancelFunc

	waitGroup sync.WaitGroup

	pendingMu sync.Mutex
	pending   map[uuid.UUID]struct{}

	processedCount atomic.Uint64
	createdCount   atomic.Uint64
	skippedCount   atomic.Uint64
	failedCount    atomic.Uint64
}

func NewWorker(
	service *Service,
	logger *zap.Logger,
	workerCount int,
	queueCapacity int,
	analysisTimeout time.Duration,
) (*Worker, error) {
	if service == nil {
		return nil, errors.New(
			"pre-encryption service is required",
		)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	if workerCount <= 0 {
		workerCount =
			defaultWorkerCount
	}

	if queueCapacity <= 0 {
		queueCapacity =
			defaultQueueCapacity
	}

	if analysisTimeout <= 0 {
		analysisTimeout =
			defaultAnalysisTimeout
	}

	return &Worker{
		service: service,
		logger:  logger,

		workerCount: workerCount,

		analysisTimeout: analysisTimeout,

		queue: make(
			chan analysisJob,
			queueCapacity,
		),

		pending: make(
			map[uuid.UUID]struct{},
		),
	}, nil
}

func (w *Worker) Start(
	parentContext context.Context,
) error {
	if w == nil || w.service == nil {
		return errors.New(
			"pre-encryption worker is unavailable",
		)
	}

	if parentContext == nil {
		return errors.New(
			"pre-encryption worker context is required",
		)
	}

	w.stateMu.Lock()
	defer w.stateMu.Unlock()

	if w.started {
		return errors.New(
			"pre-encryption worker is already started",
		)
	}

	workerContext, cancel :=
		context.WithCancel(
			parentContext,
		)

	w.cancel = cancel
	w.started = true

	for workerIndex := 1; workerIndex <= w.workerCount; workerIndex++ {
		w.waitGroup.Add(1)

		go w.runWorker(
			workerContext,
			workerIndex,
		)
	}

	w.waitGroup.Add(1)

	go w.runCorrelationMaintenance(
		workerContext,
	)

	w.logger.Info(
		"Pre-encryption detection worker started",
		zap.Int(
			"worker_count",
			w.workerCount,
		),
		zap.Int(
			"queue_capacity",
			cap(w.queue),
		),
		zap.Duration(
			"analysis_timeout",
			w.analysisTimeout,
		),

		zap.Duration(
			"correlation_interval",
			defaultCorrelationMaintenanceInterval,
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

	w.stateMu.Lock()

	if !w.started {
		w.stateMu.Unlock()
		return nil
	}

	cancel := w.cancel

	w.started = false
	w.cancel = nil

	w.stateMu.Unlock()

	if cancel != nil {
		cancel()
	}

	completed := make(
		chan struct{},
	)

	go func() {
		w.waitGroup.Wait()
		close(completed)
	}()

	select {
	case <-completed:
		w.pendingMu.Lock()

		clear(w.pending)

		w.pendingMu.Unlock()

		w.logger.Info(
			"Pre-encryption detection worker stopped",
			zap.Uint64(
				"processed",
				w.processedCount.Load(),
			),
			zap.Uint64(
				"created",
				w.createdCount.Load(),
			),
			zap.Uint64(
				"skipped",
				w.skippedCount.Load(),
			),
			zap.Uint64(
				"failed",
				w.failedCount.Load(),
			),
		)

		return nil

	case <-ctx.Done():
		return ctx.Err()
	}
}

// TrySubmitFileEventAnalysis implements the interface used
// by the HoneyToken File Event Service.
func (w *Worker) TrySubmitFileEventAnalysis(
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
) bool {
	if w == nil ||
		organizationID == uuid.Nil ||
		fileEventID == uuid.Nil {
		return false
	}

	w.stateMu.RLock()
	started := w.started
	w.stateMu.RUnlock()

	if !started {
		return false
	}

	w.pendingMu.Lock()

	if _, exists :=
		w.pending[fileEventID]; exists {
		w.pendingMu.Unlock()

		return true
	}

	w.pending[fileEventID] =
		struct{}{}

	w.pendingMu.Unlock()

	job := analysisJob{
		OrganizationID: organizationID,

		FileEventID: fileEventID,
	}

	select {
	case w.queue <- job:
		return true

	default:
		w.removePending(
			fileEventID,
		)

		w.logger.Warn(
			"Pre-encryption detection queue is full",
			zap.String(
				"organization_id",
				organizationID.String(),
			),
			zap.String(
				"file_event_id",
				fileEventID.String(),
			),
		)

		return false
	}
}

func (w *Worker) runWorker(
	ctx context.Context,
	workerIndex int,
) {
	defer w.waitGroup.Done()

	for {
		select {
		case <-ctx.Done():
			return

		case job := <-w.queue:
			w.processJob(
				ctx,
				workerIndex,
				job,
			)
		}
	}
}

func (w *Worker) processJob(
	workerContext context.Context,
	workerIndex int,
	job analysisJob,
) {
	defer w.removePending(
		job.FileEventID,
	)

	analysisContext, cancel :=
		context.WithTimeout(
			workerContext,
			w.analysisTimeout,
		)
	defer cancel()

	result, err :=
		w.service.AnalyzeFileEvent(
			analysisContext,
			job.OrganizationID,
			job.FileEventID,
		)

	if err != nil {
		w.failedCount.Add(1)

		w.logger.Error(
			"Pre-encryption file event analysis failed",
			zap.Int(
				"worker_index",
				workerIndex,
			),
			zap.String(
				"organization_id",
				job.OrganizationID.String(),
			),
			zap.String(
				"file_event_id",
				job.FileEventID.String(),
			),
			zap.Error(err),
		)

		return
	}

	w.processedCount.Add(1)

	if result == nil {
		w.skippedCount.Add(1)
		return
	}

	if result.EngineFallback &&
		result.EngineError != nil {
		w.logger.Warn(
			"Pre-encryption AI engine fallback applied",
			zap.Int(
				"worker_index",
				workerIndex,
			),
			zap.String(
				"file_event_id",
				job.FileEventID.String(),
			),
			zap.Error(
				result.EngineError,
			),
		)
	}

	if result.Skipped {
		w.skippedCount.Add(1)

		w.logger.Debug(
			"Pre-encryption file event skipped",
			zap.Int(
				"worker_index",
				workerIndex,
			),
			zap.String(
				"file_event_id",
				job.FileEventID.String(),
			),
			zap.String(
				"reason",
				result.SkippedReason,
			),
		)

		return
	}

	if !result.Created ||
		result.Detection == nil {
		return
	}

	w.createdCount.Add(1)

	w.logger.Warn(
		"Pre-encryption ransomware behaviour detected",
		zap.Int(
			"worker_index",
			workerIndex,
		),
		zap.String(
			"organization_id",
			job.OrganizationID.String(),
		),
		zap.String(
			"file_event_id",
			job.FileEventID.String(),
		),
		zap.String(
			"detection_id",
			result.Detection.ID.String(),
		),
		zap.String(
			"detection_code",
			result.Detection.DetectionCode,
		),
		zap.Float64(
			"combined_risk_score",
			result.Detection.
				CombinedRiskScore,
		),
		zap.String(
			"risk_level",
			result.Detection.RiskLevel,
		),
		zap.String(
			"classification",
			result.Detection.
				Classification,
		),
		zap.String(
			"detection_stage",
			result.Detection.
				DetectionStage,
		),
		zap.Bool(
			"requires_endpoint_isolation",
			result.Detection.
				RequiresEndpointIsolation,
		),
	)
}

func (w *Worker) runCorrelationMaintenance(
	ctx context.Context,
) {
	defer w.waitGroup.Done()

	w.refreshPendingCorrelations(ctx)

	ticker := time.NewTicker(
		defaultCorrelationMaintenanceInterval,
	)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			w.refreshPendingCorrelations(ctx)
		}
	}
}

func (w *Worker) refreshPendingCorrelations(
	parentContext context.Context,
) {
	if w == nil || w.service == nil {
		return
	}

	maintenanceContext, cancel :=
		context.WithTimeout(
			parentContext,
			defaultCorrelationMaintenanceTimeout,
		)
	defer cancel()

	updatedCount, err :=
		w.service.
			RefreshPendingDetectionCorrelations(
				maintenanceContext,
				defaultCorrelationBatchSize,
			)
	if err != nil {
		if errors.Is(
			err,
			context.Canceled,
		) {
			return
		}

		w.logger.Error(
			"Pre-encryption detection correlation maintenance failed",
			zap.Error(err),
		)

		return
	}

	if updatedCount > 0 {
		w.logger.Info(
			"Pre-encryption detection correlations refreshed",
			zap.Int64(
				"updated_count",
				updatedCount,
			),
		)
	}
}

func (w *Worker) removePending(
	fileEventID uuid.UUID,
) {
	w.pendingMu.Lock()

	delete(
		w.pending,
		fileEventID,
	)

	w.pendingMu.Unlock()
}
