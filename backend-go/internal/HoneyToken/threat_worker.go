package honeytoken

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	defaultThreatWorkerCount = 4
	defaultThreatQueueSize   = 256
	threatProcessingTimeout  = 30 * time.Second
)

const incidentAutomationTimeout = 15 * time.Second

var (
	ErrThreatWorkerNotRunning = errors.New(
		"threat worker is not running",
	)

	ErrThreatWorkerStopped = errors.New(
		"threat worker has stopped",
	)
)

// ThreatWorkerStats contains background threat-processing statistics.
type ThreatWorkerStats struct {
	Queued    uint64 `json:"queued"`
	Processed uint64 `json:"processed"`
	Failed    uint64 `json:"failed"`
	Dropped   uint64 `json:"dropped"`
}

// ThreatWorker asynchronously processes normalized security signals.
type ThreatWorker struct {
	engine                        *ThreatEngine
	logger                        *zap.Logger
	queue                         chan ThreatSignal
	incidentAutomation            *IncidentAutomationService
	attackStoryPublisher          AttackStoryPublisher
	securityNotificationPublisher SecurityNotificationPublisher

	workerCount int

	mu      sync.RWMutex
	started bool
	stopped bool
	cancel  context.CancelFunc
	wait    sync.WaitGroup

	queuedCount    atomic.Uint64
	processedCount atomic.Uint64
	failedCount    atomic.Uint64
	droppedCount   atomic.Uint64
}

func NewThreatWorker(
	engine *ThreatEngine,
	logger *zap.Logger,
	workerCount int,
	queueSize int,
) (*ThreatWorker, error) {
	if engine == nil {
		return nil, errors.New(
			"threat engine is required",
		)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	if workerCount == 0 {
		workerCount = defaultThreatWorkerCount
	}

	if workerCount < 1 || workerCount > 32 {
		return nil, errors.New(
			"threat worker count must be between 1 and 32",
		)
	}

	if queueSize == 0 {
		queueSize = defaultThreatQueueSize
	}

	if queueSize < workerCount ||
		queueSize > 10000 {
		return nil, fmt.Errorf(
			"threat queue size must be between %d and 10000",
			workerCount,
		)
	}

	return &ThreatWorker{
		engine:      engine,
		logger:      logger,
		queue:       make(chan ThreatSignal, queueSize),
		workerCount: workerCount,
	}, nil
}

// SetIncidentAutomationService connects successful Threat Engine results to
// automatic Incident Engine escalation.
func (w *ThreatWorker) SetIncidentAutomationService(
	service *IncidentAutomationService,
) {
	if w == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.incidentAutomation = service
}

// SetSecurityNotificationPublisher connects the Threat Engine worker to the
// Notification Engine without creating a direct package dependency.
func (w *ThreatWorker) SetSecurityNotificationPublisher(
	publisher SecurityNotificationPublisher,
) {
	if w == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.securityNotificationPublisher = publisher
}

// SetAttackStoryPublisher connects correlated threat activity to the
// organization attack-story timeline without adding a package dependency.
func (w *ThreatWorker) SetAttackStoryPublisher(
	publisher AttackStoryPublisher,
) {
	if w == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.attackStoryPublisher = publisher
}

// Start launches the configured threat-processing goroutines.
func (w *ThreatWorker) Start(
	parent context.Context,
) error {
	if w == nil {
		return errors.New(
			"threat worker is unavailable",
		)
	}

	if parent == nil {
		parent = context.Background()
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.stopped {
		return ErrThreatWorkerStopped
	}

	if w.started {
		return nil
	}

	workerContext, cancel :=
		context.WithCancel(parent)

	w.cancel = cancel
	w.started = true

	for workerID := 1; workerID <= w.workerCount; workerID++ {
		w.wait.Add(1)

		go w.runWorker(
			workerContext,
			workerID,
		)
	}

	w.logger.Info(
		"Threat Engine worker started",
		zap.Int(
			"worker_count",
			w.workerCount,
		),
		zap.Int(
			"queue_capacity",
			cap(w.queue),
		),
	)

	return nil
}

// Submit queues a threat signal and waits until queue capacity is available or
// the provided context is cancelled.
func (w *ThreatWorker) Submit(
	ctx context.Context,
	signal ThreatSignal,
) error {
	if w == nil {
		return errors.New(
			"threat worker is unavailable",
		)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if err := w.runningError(); err != nil {
		return err
	}

	select {
	case w.queue <- signal:
		w.queuedCount.Add(1)

		return nil

	case <-ctx.Done():
		w.droppedCount.Add(1)

		return fmt.Errorf(
			"queue threat signal: %w",
			ctx.Err(),
		)
	}
}

// TrySubmit queues a signal without blocking. It returns false when the worker
// is stopped or the queue is currently full.
func (w *ThreatWorker) TrySubmit(
	signal ThreatSignal,
) bool {
	if w == nil {
		return false
	}

	if err := w.runningError(); err != nil {
		w.droppedCount.Add(1)

		return false
	}

	select {
	case w.queue <- signal:
		w.queuedCount.Add(1)

		return true

	default:
		w.droppedCount.Add(1)

		w.logger.Warn(
			"Threat signal queue is full",
			zap.String(
				"file_event_id",
				signal.FileEventID.String(),
			),
			zap.String(
				"organization_id",
				signal.OrganizationID.String(),
			),
		)

		return false
	}
}

// Stop gracefully cancels workers and waits for them to exit.
func (w *ThreatWorker) Stop(
	ctx context.Context,
) error {
	if w == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	w.mu.Lock()

	if w.stopped {
		w.mu.Unlock()

		return nil
	}

	w.stopped = true
	w.started = false

	cancel := w.cancel

	w.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	completed := make(chan struct{})

	go func() {
		w.wait.Wait()
		close(completed)
	}()

	select {
	case <-completed:
		w.logger.Info(
			"Threat Engine worker stopped",
			zap.Uint64(
				"processed",
				w.processedCount.Load(),
			),
			zap.Uint64(
				"failed",
				w.failedCount.Load(),
			),
		)

		return nil

	case <-ctx.Done():
		return fmt.Errorf(
			"stop threat worker: %w",
			ctx.Err(),
		)
	}
}

// Stats returns a thread-safe processing statistics snapshot.
func (w *ThreatWorker) Stats() ThreatWorkerStats {
	if w == nil {
		return ThreatWorkerStats{}
	}

	return ThreatWorkerStats{
		Queued:    w.queuedCount.Load(),
		Processed: w.processedCount.Load(),
		Failed:    w.failedCount.Load(),
		Dropped:   w.droppedCount.Load(),
	}
}

func (w *ThreatWorker) runWorker(
	ctx context.Context,
	workerID int,
) {
	defer w.wait.Done()

	for {
		select {
		case <-ctx.Done():
			return

		case signal := <-w.queue:
			w.processSignal(
				ctx,
				workerID,
				signal,
			)
		}
	}
}

func (w *ThreatWorker) processSignal(
	parent context.Context,
	workerID int,
	signal ThreatSignal,
) {
	processingContext, cancel :=
		context.WithTimeout(
			parent,
			threatProcessingTimeout,
		)
	defer cancel()

	claimed, err :=
		w.engine.repository.
			ClaimFileEventForThreatAnalysis(
				processingContext,
				signal.OrganizationID,
				signal.FileEventID,
			)
	if err != nil {
		w.failedCount.Add(1)

		w.logger.Error(
			"Failed to claim file event for Threat Engine",
			zap.Int(
				"worker_id",
				workerID,
			),
			zap.String(
				"file_event_id",
				signal.FileEventID.String(),
			),
			zap.Error(err),
		)

		return
	}

	if !claimed {
		w.logger.Debug(
			"File event was already claimed or processed",
			zap.Int(
				"worker_id",
				workerID,
			),
			zap.String(
				"file_event_id",
				signal.FileEventID.String(),
			),
		)

		return
	}

	result, err := w.engine.Analyze(
		processingContext,
		signal,
	)
	if err != nil {
		w.failedCount.Add(1)

		failureContext, failureCancel :=
			context.WithTimeout(
				context.Background(),
				5*time.Second,
			)

		statusError :=
			w.engine.repository.
				MarkFileEventThreatFailed(
					failureContext,
					signal.OrganizationID,
					signal.FileEventID,
					"Threat Engine analysis failed",
				)

		failureCancel()

		w.logger.Error(
			"Threat signal processing failed",
			zap.Int(
				"worker_id",
				workerID,
			),
			zap.String(
				"file_event_id",
				signal.FileEventID.String(),
			),
			zap.String(
				"organization_id",
				signal.OrganizationID.String(),
			),
			zap.Error(err),
			zap.NamedError(
				"status_update_error",
				statusError,
			),
		)

		return
	}

	err = w.engine.repository.
		MarkFileEventThreatProcessed(
			processingContext,
			signal.OrganizationID,
			signal.FileEventID,
		)
	if err != nil {
		w.failedCount.Add(1)

		failureContext, failureCancel :=
			context.WithTimeout(
				context.Background(),
				5*time.Second,
			)

		statusError :=
			w.engine.repository.
				MarkFileEventThreatFailed(
					failureContext,
					signal.OrganizationID,
					signal.FileEventID,
					"Threat Engine status completion failed",
				)

		failureCancel()

		w.logger.Error(
			"Failed to complete file event threat status",
			zap.Int(
				"worker_id",
				workerID,
			),
			zap.String(
				"file_event_id",
				signal.FileEventID.String(),
			),
			zap.Error(err),
			zap.NamedError(
				"failure_status_error",
				statusError,
			),
		)

		return
	}

	w.processedCount.Add(1)

	if result == nil ||
		result.Threat == nil {
		w.logger.Debug(
			"File event processed without creating a threat",
			zap.Int(
				"worker_id",
				workerID,
			),
			zap.String(
				"file_event_id",
				signal.FileEventID.String(),
			),
		)

		return
	}

	w.logger.Info(
		"Threat signal processed",
		zap.Int(
			"worker_id",
			workerID,
		),
		zap.String(
			"file_event_id",
			signal.FileEventID.String(),
		),
		zap.String(
			"threat_id",
			result.Threat.ID,
		),
		zap.Bool(
			"threat_created",
			result.ThreatCreated,
		),
		zap.String(
			"severity",
			result.Threat.Severity,
		),
	)

	if notificationErr :=
		w.publishThreatDetectedNotification(
			processingContext,
			result.Threat,
			result.ThreatCreated,
			signal.FileEventID,
		); notificationErr != nil {
		w.logger.Error(
			"Threat notification publication failed",
			zap.Int(
				"worker_id",
				workerID,
			),
			zap.String(
				"file_event_id",
				signal.FileEventID.String(),
			),
			zap.String(
				"threat_id",
				result.Threat.ID,
			),
			zap.Error(notificationErr),
		)
	}

	if storyErr := w.publishAttackStoryActivity(
		processingContext,
		result.Threat,
		signal,
	); storyErr != nil {
		w.logger.Error(
			"Attack story activity publication failed",
			zap.String("file_event_id", signal.FileEventID.String()),
			zap.String("threat_id", result.Threat.ID),
			zap.Error(storyErr),
		)
	}

	w.processIncidentAutomation(
		parent,
		workerID,
		result.Threat,
	)
}

func (w *ThreatWorker) processIncidentAutomation(
	parent context.Context,
	workerID int,
	threat *ThreatResponse,
) {
	service := w.incidentAutomationService()
	if service == nil || threat == nil {
		return
	}

	automationContext, cancel :=
		context.WithTimeout(
			parent,
			incidentAutomationTimeout,
		)
	defer cancel()

	result, err :=
		service.CreateFromThreatResponse(
			automationContext,
			threat,
		)
	if err != nil {
		w.logger.Error(
			"Automatic incident creation failed",
			zap.Int(
				"worker_id",
				workerID,
			),
			zap.String(
				"threat_id",
				threat.ID,
			),
			zap.String(
				"organization_id",
				threat.OrganizationID,
			),
			zap.Error(err),
		)

		return
	}

	if result == nil {
		return
	}

	if result.Incident == nil {
		w.logger.Debug(
			"Threat did not require automatic incident creation",
			zap.Int(
				"worker_id",
				workerID,
			),
			zap.String(
				"threat_id",
				threat.ID,
			),
			zap.String(
				"reason",
				result.Reason,
			),
		)

		return
	}

	w.logger.Info(
		"Incident automation processed",
		zap.Int(
			"worker_id",
			workerID,
		),
		zap.String(
			"threat_id",
			threat.ID,
		),
		zap.String(
			"incident_id",
			result.Incident.ID,
		),
		zap.String(
			"incident_number",
			result.Incident.IncidentNumber,
		),
		zap.Bool(
			"incident_created",
			result.IncidentCreated,
		),
		zap.String(
			"reason",
			result.Reason,
		),
	)
	if notificationErr :=
		w.publishIncidentCreatedNotification(
			automationContext,
			threat,
			result.Incident.ID,
			result.Incident.IncidentNumber,
			result.IncidentCreated,
		); notificationErr != nil {
		w.logger.Error(
			"Incident notification publication failed",
			zap.Int(
				"worker_id",
				workerID,
			),
			zap.String(
				"threat_id",
				threat.ID,
			),
			zap.String(
				"incident_id",
				result.Incident.ID,
			),
			zap.String(
				"incident_number",
				result.Incident.IncidentNumber,
			),
			zap.Error(notificationErr),
		)
	}
}

func (w *ThreatWorker) incidentAutomationService() *IncidentAutomationService {
	if w == nil {
		return nil
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	return w.incidentAutomation
}

func (w *ThreatWorker) runningError() error {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.stopped {
		return ErrThreatWorkerStopped
	}

	if !w.started {
		return ErrThreatWorkerNotRunning
	}

	return nil
}
