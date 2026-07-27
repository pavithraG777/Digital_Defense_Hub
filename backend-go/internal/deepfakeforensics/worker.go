package deepfakeforensics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	defaultAnalysisWorkerCount = 2
	maximumAnalysisWorkerCount = 16

	defaultAnalysisPollInterval = time.Second
	defaultAnalysisTimeout      = 10 * time.Minute
	analysisFailureTimeout      = 15 * time.Second
)

var (
	ErrAnalysisWorkerUnavailable = errors.New(
		"deepfake forensics analysis worker is unavailable",
	)
	ErrAnalysisWorkerStopped = errors.New(
		"deepfake forensics analysis worker has stopped",
	)
)

// AnalysisWorkerStats contains a thread-safe snapshot of
// background multimodal job processing.
type AnalysisWorkerStats struct {
	Claimed   uint64 `json:"claimed"`
	Processed uint64 `json:"processed"`
	Retried   uint64 `json:"retried"`
	Failed    uint64 `json:"failed"`
}

// AnalysisWorker polls PostgreSQL for organization-scoped
// jobs and executes them through the offline Python engine.
type AnalysisWorker struct {
	repository   *Repository
	engineClient *EngineClient
	logger       *zap.Logger

	trustEscalationPublisher MediaTrustEscalationPublisher

	workerCount     int
	pollInterval    time.Duration
	analysisTimeout time.Duration
	processingNode  string

	mu      sync.RWMutex
	started bool
	stopped bool
	cancel  context.CancelFunc
	wait    sync.WaitGroup

	claimedCount   atomic.Uint64
	processedCount atomic.Uint64
	retriedCount   atomic.Uint64
	failedCount    atomic.Uint64
}

// NewAnalysisWorker creates the durable database-backed
// multimodal analysis worker.
func NewAnalysisWorker(
	repository *Repository,
	engineClient *EngineClient,
	logger *zap.Logger,
	workerCount int,
	pollInterval time.Duration,
	analysisTimeout time.Duration,
	processingNode string,
) (*AnalysisWorker, error) {
	if repository == nil ||
		!repository.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	if engineClient == nil ||
		!engineClient.isAvailable() {
		return nil, ErrMediaEngineUnavailable
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	if workerCount == 0 {
		workerCount =
			defaultAnalysisWorkerCount
	}
	if workerCount < 1 ||
		workerCount >
			maximumAnalysisWorkerCount {
		return nil, fmt.Errorf(
			"analysis worker count must be between 1 and %d",
			maximumAnalysisWorkerCount,
		)
	}

	if pollInterval <= 0 {
		pollInterval =
			defaultAnalysisPollInterval
	}
	if analysisTimeout <= 0 {
		analysisTimeout =
			defaultAnalysisTimeout
	}

	processingNode = strings.TrimSpace(
		processingNode,
	)
	if processingNode == "" {
		hostName, err := os.Hostname()
		if err != nil ||
			strings.TrimSpace(hostName) == "" {
			hostName = "local"
		}

		processingNode =
			"deepfake-forensics-" +
				strings.TrimSpace(hostName)
	}

	return &AnalysisWorker{
		repository:      repository,
		engineClient:    engineClient,
		logger:          logger,
		workerCount:     workerCount,
		pollInterval:    pollInterval,
		analysisTimeout: analysisTimeout,
		processingNode:  processingNode,
	}, nil
}

// Start launches the configured database polling workers.
func (w *AnalysisWorker) Start(
	parent context.Context,
) error {
	if w == nil ||
		w.repository == nil ||
		w.engineClient == nil {
		return ErrAnalysisWorkerUnavailable
	}

	if parent == nil {
		parent = context.Background()
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.stopped {
		return ErrAnalysisWorkerStopped
	}
	if w.started {
		return nil
	}

	workerContext, cancel :=
		context.WithCancel(parent)

	w.cancel = cancel
	w.started = true

	for workerIndex := 1; workerIndex <= w.workerCount; workerIndex++ {
		w.wait.Add(1)

		go w.runWorker(
			workerContext,
			workerIndex,
		)
	}

	w.logger.Info(
		"Deepfake forensics analysis worker started",
		zap.Int(
			"worker_count",
			w.workerCount,
		),
		zap.Duration(
			"poll_interval",
			w.pollInterval,
		),
		zap.Duration(
			"analysis_timeout",
			w.analysisTimeout,
		),
		zap.String(
			"processing_node",
			w.processingNode,
		),
	)

	return nil
}

// Stop gracefully cancels polling and waits for active
// workers to finish their current cancellation handling.
func (w *AnalysisWorker) Stop(
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
		stats := w.Stats()

		w.logger.Info(
			"Deepfake forensics analysis worker stopped",
			zap.Uint64(
				"claimed",
				stats.Claimed,
			),
			zap.Uint64(
				"processed",
				stats.Processed,
			),
			zap.Uint64(
				"retried",
				stats.Retried,
			),
			zap.Uint64(
				"failed",
				stats.Failed,
			),
		)

		return nil

	case <-ctx.Done():
		return fmt.Errorf(
			"stop deepfake forensics worker: %w",
			ctx.Err(),
		)
	}
}

// Stats returns the current worker counters.
func (w *AnalysisWorker) Stats() AnalysisWorkerStats {
	if w == nil {
		return AnalysisWorkerStats{}
	}

	return AnalysisWorkerStats{
		Claimed:   w.claimedCount.Load(),
		Processed: w.processedCount.Load(),
		Retried:   w.retriedCount.Load(),
		Failed:    w.failedCount.Load(),
	}
}

func (w *AnalysisWorker) runWorker(
	ctx context.Context,
	workerIndex int,
) {
	defer w.wait.Done()

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
			processedJob := w.processNextJob(
				ctx,
				workerIndex,
			)

			nextPoll := w.pollInterval
			if processedJob {
				nextPoll = 0
			}

			timer.Reset(nextPoll)
		}
	}
}

func (w *AnalysisWorker) processNextJob(
	parent context.Context,
	workerIndex int,
) bool {
	processingNode := w.processingNode +
		"-worker-" +
		strconv.Itoa(workerIndex)

	jobs, err := w.repository.ClaimAnalysisJobs(
		parent,
		1,
		processingNode,
	)
	if err != nil {
		if parent.Err() == nil {
			w.logger.Error(
				"Failed to claim media analysis job",
				zap.Int(
					"worker_index",
					workerIndex,
				),
				zap.Error(err),
			)
		}

		return false
	}
	if len(jobs) == 0 {
		return false
	}

	job := jobs[0]
	w.claimedCount.Add(1)

	w.processClaimedJob(
		parent,
		workerIndex,
		job,
	)

	return true
}

func (w *AnalysisWorker) processClaimedJob(
	parent context.Context,
	workerIndex int,
	job AIAnalysisJob,
) {
	startedAt := time.Now().UTC()

	processingContext, cancel :=
		context.WithTimeout(
			parent,
			w.analysisTimeout,
		)
	defer cancel()

	source, err := w.repository.LoadAnalysisSource(
		processingContext,
		job.ID,
	)
	if err != nil {
		w.handleJobFailure(
			workerIndex,
			job,
			nil,
			"ANALYSIS_SOURCE_LOAD_FAILED",
			err,
			time.Since(startedAt),
		)
		return
	}

	if err = w.repository.UpdateAnalysisJobProgress(
		processingContext,
		job.ID,
		15,
	); err != nil {
		w.handleJobFailure(
			workerIndex,
			job,
			nil,
			"ANALYSIS_PROGRESS_UPDATE_FAILED",
			err,
			time.Since(startedAt),
		)
		return
	}

	engineRequest, err :=
		BuildMediaEngineRequest(*source)
	if err != nil {
		w.handleJobFailure(
			workerIndex,
			job,
			nil,
			"ANALYSIS_REQUEST_INVALID",
			err,
			time.Since(startedAt),
		)
		return
	}

	if err = w.repository.UpdateAnalysisJobProgress(
		processingContext,
		job.ID,
		25,
	); err != nil {
		w.handleJobFailure(
			workerIndex,
			job,
			nil,
			"ANALYSIS_PROGRESS_UPDATE_FAILED",
			err,
			time.Since(startedAt),
		)
		return
	}

	engineResponse, err :=
		w.engineClient.Analyze(
			processingContext,
			engineRequest,
		)
	if err != nil {
		w.handleJobFailure(
			workerIndex,
			job,
			engineResponse,
			analysisFailureCode(err),
			err,
			time.Since(startedAt),
		)
		return
	}

	if err = w.repository.UpdateAnalysisJobProgress(
		processingContext,
		job.ID,
		85,
	); err != nil {
		w.handleJobFailure(
			workerIndex,
			job,
			engineResponse,
			"ANALYSIS_PROGRESS_UPDATE_FAILED",
			err,
			time.Since(startedAt),
		)
		return
	}

	bundle, err := BuildAnalysisResultBundle(
		*source,
		engineResponse,
	)
	if err != nil {
		w.handleJobFailure(
			workerIndex,
			job,
			engineResponse,
			"ANALYSIS_RESULT_MAPPING_FAILED",
			err,
			time.Since(startedAt),
		)
		return
	}

	if err = w.repository.PersistAnalysisResult(
		processingContext,
		*source,
		engineResponse,
		bundle,
	); err != nil {
		w.handleJobFailure(
			workerIndex,
			job,
			engineResponse,
			"ANALYSIS_RESULT_PERSISTENCE_FAILED",
			err,
			time.Since(startedAt),
		)
		return
	}

	w.updateTrustAndEscalate(
		parent,
		*source,
	)

	w.processedCount.Add(1)

	w.logger.Info(
		"Media analysis job completed",
		zap.Int(
			"worker_index",
			workerIndex,
		),
		zap.String(
			"organization_id",
			job.OrganizationID.String(),
		),
		zap.String(
			"analysis_job_id",
			job.ID.String(),
		),
		zap.String(
			"job_type",
			job.JobType,
		),
		zap.String(
			"runtime",
			engineResponse.Runtime,
		),
		zap.Int64(
			"processing_duration_ms",
			engineResponse.ProcessingDurationMS,
		),
	)
}

func (w *AnalysisWorker) handleJobFailure(
	workerIndex int,
	job AIAnalysisJob,
	engineResponse *MediaEngineResponse,
	errorCode string,
	processingError error,
	elapsed time.Duration,
) {
	failureContext, cancel :=
		context.WithTimeout(
			context.Background(),
			analysisFailureTimeout,
		)
	defer cancel()

	responseData := buildFailureResponseData(
		engineResponse,
		processingError,
	)

	durationMS := elapsed.Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	if engineResponse != nil &&
		engineResponse.ProcessingDurationMS >
			durationMS {
		durationMS =
			engineResponse.ProcessingDurationMS
	}

	updatedJob, updateError :=
		w.repository.RetryOrFailAnalysisJob(
			failureContext,
			job.ID,
			errorCode,
			safeAnalysisErrorMessage(
				processingError,
			),
			durationMS,
			responseData,
		)
	if updateError != nil {
		w.failedCount.Add(1)

		w.logger.Error(
			"Failed to record media analysis job failure",
			zap.Int(
				"worker_index",
				workerIndex,
			),
			zap.String(
				"organization_id",
				job.OrganizationID.String(),
			),
			zap.String(
				"analysis_job_id",
				job.ID.String(),
			),
			zap.String(
				"error_code",
				errorCode,
			),
			zap.Error(processingError),
			zap.NamedError(
				"status_update_error",
				updateError,
			),
		)

		return
	}

	if updatedJob.Status == JobStatusFailed {
		w.failedCount.Add(1)

		w.logger.Error(
			"Media analysis job failed permanently",
			zap.Int(
				"worker_index",
				workerIndex,
			),
			zap.String(
				"organization_id",
				job.OrganizationID.String(),
			),
			zap.String(
				"analysis_job_id",
				job.ID.String(),
			),
			zap.String(
				"job_type",
				job.JobType,
			),
			zap.String(
				"error_code",
				errorCode,
			),
			zap.Int(
				"retry_count",
				updatedJob.RetryCount,
			),
			zap.Error(processingError),
		)

		return
	}

	w.retriedCount.Add(1)

	w.logger.Warn(
		"Media analysis job scheduled for retry",
		zap.Int(
			"worker_index",
			workerIndex,
		),
		zap.String(
			"organization_id",
			job.OrganizationID.String(),
		),
		zap.String(
			"analysis_job_id",
			job.ID.String(),
		),
		zap.String(
			"job_type",
			job.JobType,
		),
		zap.String(
			"error_code",
			errorCode,
		),
		zap.Int(
			"retry_count",
			updatedJob.RetryCount,
		),
		zap.Error(processingError),
	)
}

func analysisFailureCode(
	err error,
) string {
	switch {
	case errors.Is(
		err,
		context.DeadlineExceeded,
	):
		return "MEDIA_ANALYSIS_TIMEOUT"

	case errors.Is(
		err,
		ErrMediaEngineUnavailable,
	):
		return "MEDIA_ENGINE_UNAVAILABLE"

	case errors.Is(
		err,
		ErrMediaEngineExecutionFailed,
	):
		return "MEDIA_ENGINE_EXECUTION_FAILED"

	case errors.Is(
		err,
		ErrInvalidMediaEngineResponse,
	):
		return "MEDIA_ENGINE_RESPONSE_INVALID"

	default:
		return "MEDIA_ANALYSIS_FAILED"
	}
}

func buildFailureResponseData(
	engineResponse *MediaEngineResponse,
	processingError error,
) map[string]any {
	responseData := map[string]any{
		"failed_at": time.Now().UTC(),
		"error": safeAnalysisErrorMessage(
			processingError,
		),
	}

	if engineResponse == nil {
		return responseData
	}

	engineData, err := valueToMap(
		engineResponse,
	)
	if err != nil {
		responseData["response_encoding_error"] =
			err.Error()
		return responseData
	}

	for key, value := range engineData {
		responseData[key] = value
	}

	return responseData
}

func safeAnalysisErrorMessage(
	err error,
) string {
	if err == nil {
		return "media analysis failed"
	}

	message := strings.TrimSpace(
		err.Error(),
	)
	if message == "" {
		return "media analysis failed"
	}
	if len(message) >
		maximumMediaEngineErrorLength {
		message =
			message[:maximumMediaEngineErrorLength]
	}

	return message
}
