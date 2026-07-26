package adaptivedeception

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	ErrFingerprintWorkerAlreadyStarted = errors.New(
		"canary fingerprint worker is already started",
	)

	ErrFingerprintWorkerStopped = errors.New(
		"canary fingerprint worker cannot be restarted",
	)
)

const (
	defaultFingerprintWorkerCount   = 2
	defaultFingerprintQueueCapacity = 256
	defaultFingerprintTimeout       = 30 * time.Second
)

type fingerprintJob struct {
	organizationID uuid.UUID
	fileEventID    uuid.UUID
}

// FingerprintWorker asynchronously converts persisted
// CANARY_FILE events into behavioural fingerprints.
type FingerprintWorker struct {
	repository *Repository
	service    *FingerprintService
	logger     *zap.Logger

	workerCount int
	timeout     time.Duration

	jobs chan fingerprintJob

	stateMutex sync.Mutex
	started    bool
	stopped    bool
	cancel     context.CancelFunc

	waitGroup sync.WaitGroup
}

func NewFingerprintWorker(
	repository *Repository,
	service *FingerprintService,
	logger *zap.Logger,
	workerCount int,
	queueCapacity int,
	timeout time.Duration,
) (*FingerprintWorker, error) {
	if repository == nil {
		return nil, errors.New(
			"adaptive deception repository is required",
		)
	}

	if service == nil {
		return nil, errors.New(
			"canary fingerprint service is required",
		)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	if workerCount <= 0 {
		workerCount =
			defaultFingerprintWorkerCount
	}

	if queueCapacity <= 0 {
		queueCapacity =
			defaultFingerprintQueueCapacity
	}

	if timeout <= 0 {
		timeout =
			defaultFingerprintTimeout
	}

	return &FingerprintWorker{
		repository: repository,
		service:    service,
		logger:     logger,

		workerCount: workerCount,
		timeout:     timeout,

		jobs: make(
			chan fingerprintJob,
			queueCapacity,
		),
	}, nil
}

func (w *FingerprintWorker) Start(
	parentContext context.Context,
) error {
	if w == nil {
		return errors.New(
			"canary fingerprint worker is unavailable",
		)
	}

	if parentContext == nil {
		return errors.New(
			"fingerprint worker context is required",
		)
	}

	w.stateMutex.Lock()
	defer w.stateMutex.Unlock()

	if w.started {
		return ErrFingerprintWorkerAlreadyStarted
	}

	if w.stopped {
		return ErrFingerprintWorkerStopped
	}

	workerContext, cancel :=
		context.WithCancel(
			parentContext,
		)

	w.cancel = cancel
	w.started = true

	for workerIndex := 1; workerIndex <=
		w.workerCount; workerIndex++ {
		w.waitGroup.Add(1)

		go w.runWorker(
			workerContext,
			workerIndex,
		)
	}

	w.logger.Info(
		"Adaptive deception fingerprint worker started",
		zap.Int(
			"worker_count",
			w.workerCount,
		),
		zap.Int(
			"queue_capacity",
			cap(w.jobs),
		),
		zap.Duration(
			"analysis_timeout",
			w.timeout,
		),
	)

	return nil
}

func (w *FingerprintWorker) Stop(
	ctx context.Context,
) error {
	if w == nil {
		return nil
	}

	w.stateMutex.Lock()

	if !w.started {
		w.stateMutex.Unlock()
		return nil
	}

	cancel := w.cancel

	w.started = false
	w.stopped = true
	w.cancel = nil

	w.stateMutex.Unlock()

	if cancel != nil {
		cancel()
	}

	completed := make(chan struct{})

	go func() {
		w.waitGroup.Wait()
		close(completed)
	}()

	select {
	case <-completed:
		w.logger.Info(
			"Adaptive deception fingerprint worker stopped",
		)

		return nil

	case <-ctx.Done():
		return fmt.Errorf(
			"stop canary fingerprint worker: %w",
			ctx.Err(),
		)
	}
}

// TrySubmitFileEventAnalysis implements the HoneyToken
// FileEventAnalysisSubmitter interface.
func (w *FingerprintWorker) TrySubmitFileEventAnalysis(
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
) bool {
	if w == nil ||
		organizationID == uuid.Nil ||
		fileEventID == uuid.Nil {
		return false
	}

	w.stateMutex.Lock()
	started := w.started
	w.stateMutex.Unlock()

	if !started {
		return false
	}

	job := fingerprintJob{
		organizationID: organizationID,
		fileEventID:    fileEventID,
	}

	select {
	case w.jobs <- job:
		return true

	default:
		w.logger.Warn(
			"Adaptive deception fingerprint queue is full",
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

func (w *FingerprintWorker) runWorker(
	ctx context.Context,
	workerIndex int,
) {
	defer w.waitGroup.Done()

	for {
		select {
		case <-ctx.Done():
			return

		case job := <-w.jobs:
			w.processJob(
				ctx,
				workerIndex,
				job,
			)
		}
	}
}

func (w *FingerprintWorker) processJob(
	parentContext context.Context,
	workerIndex int,
	job fingerprintJob,
) {
	analysisContext, cancel :=
		context.WithTimeout(
			parentContext,
			w.timeout,
		)
	defer cancel()

	input, err :=
		w.repository.
			GetCanaryInteractionInputFromFileEvent(
				analysisContext,
				job.organizationID,
				job.fileEventID,
			)
	if err != nil {
		if errors.Is(
			err,
			ErrCanaryFingerprintSourceNotApplicable,
		) {
			return
		}

		w.logger.Error(
			"Failed to load canary fingerprint source event",
			zap.Int(
				"worker_index",
				workerIndex,
			),
			zap.String(
				"organization_id",
				job.organizationID.String(),
			),
			zap.String(
				"file_event_id",
				job.fileEventID.String(),
			),
			zap.Error(err),
		)

		return
	}

	fingerprint, err :=
		w.service.RecordInteraction(
			analysisContext,
			*input,
		)
	if err != nil {
		w.logger.Error(
			"Failed to record canary interaction fingerprint",
			zap.Int(
				"worker_index",
				workerIndex,
			),
			zap.String(
				"organization_id",
				job.organizationID.String(),
			),
			zap.String(
				"file_event_id",
				job.fileEventID.String(),
			),
			zap.Error(err),
		)

		return
	}

	logMethod := w.logger.Info
	if fingerprint.IsSuspicious ||
		fingerprint.RansomwareSuspected {
		logMethod = w.logger.Warn
	}

	logMethod(
		"Canary interaction fingerprint processed",
		zap.Int(
			"worker_index",
			workerIndex,
		),
		zap.String(
			"organization_id",
			fingerprint.OrganizationID.String(),
		),
		zap.String(
			"canary_file_id",
			fingerprint.CanaryFileID.String(),
		),
		zap.String(
			"file_event_id",
			job.fileEventID.String(),
		),
		zap.String(
			"fingerprint_id",
			fingerprint.ID.String(),
		),
		zap.String(
			"fingerprint_hash",
			fingerprint.FingerprintHash,
		),
		zap.Float64(
			"behavioural_score",
			fingerprint.BehaviouralScore,
		),
		zap.Float64(
			"confidence_score",
			fingerprint.ConfidenceScore,
		),
		zap.Int(
			"occurrence_count",
			fingerprint.OccurrenceCount,
		),
		zap.Bool(
			"ransomware_suspected",
			fingerprint.RansomwareSuspected,
		),
	)
}
