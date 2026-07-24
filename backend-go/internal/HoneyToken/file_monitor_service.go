package honeytoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	ErrFileMonitorAlreadyStarted = errors.New(
		"file monitor service is already started",
	)

	ErrFileMonitorRuntimeConfigured = errors.New(
		"file monitor runtime is already configured",
	)
)

const (
	defaultFileMonitorWorkers         = 4
	defaultFileMonitorQueueSize       = 1024
	defaultFileMonitorDebounceWindow  = 750 * time.Millisecond
	defaultFileMonitorRefreshInterval = 30 * time.Second
)

type FileMonitorService struct {
	repository       *Repository
	fileEventService *FileEventService
	watcher          *fsnotify.Watcher
	logger           *zap.Logger
	threatWorker     *ThreatWorker

	targetMutex        sync.RWMutex
	targets            map[string]CanaryFile
	watchedDirectories map[string]struct{}

	debounceMutex sync.Mutex
	recentEvents  map[string]time.Time

	stateMutex sync.Mutex
	started    bool
	cancel     context.CancelFunc
	done       chan struct{}

	jobs chan fileMonitorJob
	wg   sync.WaitGroup
}

type fileMonitorJob struct {
	canary       CanaryFile
	eventType    string
	canaryStatus string
	eventPath    string
	operation    fsnotify.Op
	occurredAt   time.Time
}

func NewFileMonitorService(
	repository *Repository,
	fileEventService *FileEventService,
	logger *zap.Logger,
) (*FileMonitorService, error) {
	if repository == nil {
		return nil, errors.New(
			"file monitor repository is required",
		)
	}

	if fileEventService == nil {
		return nil, errors.New(
			"file event service is required",
		)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize filesystem watcher: %w",
			err,
		)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	return &FileMonitorService{
		repository:         repository,
		fileEventService:   fileEventService,
		watcher:            watcher,
		logger:             logger,
		targets:            make(map[string]CanaryFile),
		watchedDirectories: make(map[string]struct{}),
		recentEvents:       make(map[string]time.Time),
		jobs: make(
			chan fileMonitorJob,
			defaultFileMonitorQueueSize,
		),
	}, nil
}

// Start loads deployed Canary files and starts background event processing.
func (s *FileMonitorService) Start(
	parentContext context.Context,
) error {
	if parentContext == nil {
		parentContext = context.Background()
	}

	s.stateMutex.Lock()

	if s.started {
		s.stateMutex.Unlock()
		return ErrFileMonitorAlreadyStarted
	}

	ctx, cancel := context.WithCancel(
		parentContext,
	)

	if s.threatWorker != nil {
		if err := s.threatWorker.Start(ctx); err != nil {
			cancel()
			s.stateMutex.Unlock()

			return fmt.Errorf(
				"failed to start Threat Engine worker: %w",
				err,
			)
		}
	}

	if err := s.refreshTargets(ctx); err != nil {
		cancel()

		if s.threatWorker != nil {
			cleanupContext, cleanupCancel :=
				context.WithTimeout(
					context.Background(),
					5*time.Second,
				)

			_ = s.threatWorker.Stop(cleanupContext)
			cleanupCancel()
		}

		s.stateMutex.Unlock()
		return err
	}

	s.started = true
	s.cancel = cancel
	s.done = make(chan struct{})

	for workerIndex := 0; workerIndex <
		defaultFileMonitorWorkers; workerIndex++ {
		s.wg.Add(1)

		go s.runWorker(ctx, workerIndex)
	}

	s.wg.Add(1)
	go s.runWatcher(ctx)

	doneChannel := s.done
	s.stateMutex.Unlock()

	go func() {
		s.wg.Wait()
		close(doneChannel)
	}()

	s.logger.Info(
		"File monitor service started",
		zap.Int(
			"monitored_files",
			s.MonitoredFileCount(),
		),
		zap.Bool(
			"threat_engine_enabled",
			s.threatWorker != nil,
		),
	)

	return nil
}

// Stop gracefully terminates watchers, event workers, and the Threat Engine.
func (s *FileMonitorService) Stop(
	ctx context.Context,
) error {
	if ctx == nil {
		ctx = context.Background()
	}

	s.stateMutex.Lock()

	if !s.started {
		s.stateMutex.Unlock()
		return nil
	}

	cancel := s.cancel
	done := s.done
	threatWorker := s.threatWorker

	s.stateMutex.Unlock()

	if cancel != nil {
		cancel()
	}

	if err := s.watcher.Close(); err != nil &&
		!errors.Is(err, fsnotify.ErrClosed) {
		s.logger.Warn(
			"Filesystem watcher close failed",
			zap.Error(err),
		)
	}

	var threatWorkerError error

	if threatWorker != nil {
		threatWorkerError = threatWorker.Stop(ctx)
	}

	select {
	case <-done:
		s.logger.Info(
			"File monitor service stopped",
		)

		if threatWorkerError != nil {
			return fmt.Errorf(
				"failed to stop Threat Engine worker: %w",
				threatWorkerError,
			)
		}

		return nil

	case <-ctx.Done():
		return ctx.Err()
	}
}

// Refresh reloads deployed Canary files without restarting the API.
func (s *FileMonitorService) Refresh(
	ctx context.Context,
) error {
	return s.refreshTargets(ctx)
}

func (s *FileMonitorService) MonitoredFileCount() int {
	s.targetMutex.RLock()
	defer s.targetMutex.RUnlock()

	return len(s.targets)
}

func (s *FileMonitorService) runWatcher(
	ctx context.Context,
) {
	defer s.wg.Done()

	refreshTicker := time.NewTicker(
		defaultFileMonitorRefreshInterval,
	)
	defer refreshTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case event, open := <-s.watcher.Events:
			if !open {
				return
			}

			s.handleFilesystemEvent(ctx, event)

		case watcherError, open := <-s.watcher.Errors:
			if !open {
				return
			}

			s.logger.Error(
				"Filesystem watcher error",
				zap.Error(watcherError),
			)

		case <-refreshTicker.C:
			if err := s.refreshTargets(ctx); err != nil {
				s.logger.Error(
					"Failed to refresh monitored Canary files",
					zap.Error(err),
				)
			}

			s.removeExpiredDebounceEntries()
		}
	}
}

func (s *FileMonitorService) runWorker(
	ctx context.Context,
	workerIndex int,
) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return

		case job := <-s.jobs:
			if err := s.processFileMonitorJob(
				ctx,
				job,
			); err != nil {
				s.logger.Error(
					"Failed to process filesystem event",
					zap.Int(
						"worker_index",
						workerIndex,
					),
					zap.String(
						"canary_id",
						job.canary.ID.String(),
					),
					zap.String(
						"event_type",
						job.eventType,
					),
					zap.Error(err),
				)
			}
		}
	}
}

func (s *FileMonitorService) handleFilesystemEvent(
	ctx context.Context,
	event fsnotify.Event,
) {
	normalizedPath := normalizeMonitoredFilePath(
		event.Name,
	)

	s.targetMutex.RLock()
	canary, exists := s.targets[normalizedPath]
	s.targetMutex.RUnlock()

	if !exists {
		return
	}

	eventType, canaryStatus, supported :=
		classifyFilesystemEvent(event.Op)
	if !supported {
		return
	}

	debounceKey := canary.ID.String() +
		"|" + eventType

	if s.shouldDebounceEvent(
		debounceKey,
		time.Now().UTC(),
	) {
		return
	}

	job := fileMonitorJob{
		canary:       canary,
		eventType:    eventType,
		canaryStatus: canaryStatus,
		eventPath:    event.Name,
		operation:    event.Op,
		occurredAt:   time.Now().UTC(),
	}

	select {
	case s.jobs <- job:

	case <-ctx.Done():

	default:
		s.logger.Error(
			"File monitor queue is full",
			zap.String(
				"canary_id",
				canary.ID.String(),
			),
			zap.String(
				"event_type",
				eventType,
			),
		)
	}
}

func (s *FileMonitorService) processFileMonitorJob(
	ctx context.Context,
	job fileMonitorJob,
) error {
	var (
		currentHash   *string
		fileSizeAfter *int64
	)

	if job.eventType != EventTypeDeleted &&
		job.eventType != EventTypeRenamed {
		fileInfo, statErr := os.Stat(job.eventPath)
		if statErr != nil {
			if !errors.Is(statErr, os.ErrNotExist) {
				return fmt.Errorf(
					"failed to inspect monitored file: %w",
					statErr,
				)
			}
		} else if fileInfo.Mode().IsRegular() {
			size := fileInfo.Size()
			fileSizeAfter = &size

			hash, hashErr :=
				calculateCanaryFileSHA256(
					job.eventPath,
				)
			if hashErr != nil {
				return hashErr
			}

			currentHash = &hash
		}
	}

	previousHash := job.canary.OriginalFileHash

	deviceName, _ := os.Hostname()
	deviceIdentifier := deviceName

	rawEvent, err := json.Marshal(
		map[string]any{
			"operation": job.operation.String(),
			"path":      job.eventPath,
			"collector": fileEventCollectorForRuntime(),
		},
	)
	if err != nil {
		return fmt.Errorf(
			"failed to serialize filesystem event: %w",
			err,
		)
	}

	hashChanged := currentHash == nil ||
		!strings.EqualFold(
			*currentHash,
			job.canary.OriginalFileHash,
		)

	metadata, err := json.Marshal(
		map[string]any{
			"canary_code":   job.canary.CanaryCode,
			"expected_hash": job.canary.OriginalFileHash,
			"hash_changed":  hashChanged,
			"automated":     true,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"failed to serialize monitoring metadata: %w",
			err,
		)
	}

	request := CreateFileEventRequest{
		DepartmentID: fileMonitorUUIDString(
			job.canary.DepartmentID,
		),
		MonitoringRuleID: nil,
		ProtectedFileID:  nil,
		HoneytokenID: fileMonitorUUIDString(
			job.canary.HoneytokenID,
		),
		CanaryFileID: fileMonitorRequiredUUIDString(
			job.canary.ID,
		),
		SourceType:  FileEventSourceCanaryFile,
		EventType:   job.eventType,
		EventSource: fileEventCollectorForRuntime(),
		DetectionMethod: fileMonitorStringPointer(
			DetectionMethodRuleBased,
		),
		FileName:         job.canary.FileName,
		FilePath:         job.eventPath,
		PreviousFilePath: nil,
		FileExtension:    job.canary.FileExtension,
		MimeType:         job.canary.MimeType,
		FileSizeBefore:   job.canary.FileSizeBytes,
		FileSizeAfter:    fileSizeAfter,
		PreviousHash:     &previousHash,
		CurrentHash:      currentHash,
		HashAlgorithm: fileMonitorStringPointer(
			CanaryHashAlgorithmSHA256,
		),
		ProcessID:         nil,
		ProcessName:       nil,
		ExecutablePath:    nil,
		ParentProcessID:   nil,
		ParentProcessName: nil,
		CommandLine:       nil,
		ProcessHash:       nil,
		SystemUsername:    nil,
		DeviceName: fileMonitorOptionalStringPointer(
			deviceName,
		),
		DeviceIdentifier: fileMonitorOptionalStringPointer(
			deviceIdentifier,
		),
		MACAddress: nil,
		RawEvent:   rawEvent,
		Metadata:   metadata,
		OccurredAt: job.occurredAt.Format(
			time.RFC3339Nano,
		),
	}

	_, err = s.fileEventService.CreateFileEvent(
		ctx,
		job.canary.OrganizationID,
		nil,
		"",
		request,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to record monitored file event: %w",
			err,
		)
	}

	_, err = s.repository.RecordCanaryFileTrigger(
		ctx,
		job.canary.OrganizationID,
		job.canary.ID,
		job.canaryStatus,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to update Canary trigger state: %w",
			err,
		)
	}

	s.logger.Warn(
		"Canary filesystem event detected",
		zap.String(
			"organization_id",
			job.canary.OrganizationID.String(),
		),
		zap.String(
			"canary_id",
			job.canary.ID.String(),
		),
		zap.String(
			"event_type",
			job.eventType,
		),
		zap.String(
			"status",
			job.canaryStatus,
		),
	)

	return nil
}

func (s *FileMonitorService) refreshTargets(
	ctx context.Context,
) error {
	canaryFiles, err :=
		s.repository.ListMonitorableCanaryFiles(ctx)
	if err != nil {
		return err
	}

	newTargets := make(
		map[string]CanaryFile,
		len(canaryFiles),
	)
	requiredDirectories := make(map[string]struct{})

	for index := range canaryFiles {
		canary := canaryFiles[index]

		normalizedPath :=
			normalizeMonitoredFilePath(
				canary.FilePath,
			)
		if normalizedPath == "" {
			continue
		}

		directoryPath := filepath.Dir(
			canary.FilePath,
		)

		fileInfo, statErr := os.Stat(directoryPath)
		if statErr != nil {
			s.logger.Error(
				"Canary directory is unavailable",
				zap.String(
					"canary_id",
					canary.ID.String(),
				),
				zap.String(
					"directory",
					directoryPath,
				),
				zap.Error(statErr),
			)
			continue
		}

		if !fileInfo.IsDir() {
			s.logger.Error(
				"Canary parent path is not a directory",
				zap.String(
					"canary_id",
					canary.ID.String(),
				),
				zap.String(
					"directory",
					directoryPath,
				),
			)
			continue
		}

		newTargets[normalizedPath] = canary
		requiredDirectories[normalizeMonitoredFilePath(directoryPath)] = struct{}{}
	}

	s.targetMutex.Lock()
	defer s.targetMutex.Unlock()

	for directoryPath := range requiredDirectories {
		if _, alreadyWatched :=
			s.watchedDirectories[directoryPath]; alreadyWatched {
			continue
		}

		if err = s.watcher.Add(directoryPath); err != nil {
			s.logger.Error(
				"Failed to watch Canary directory",
				zap.String(
					"directory",
					directoryPath,
				),
				zap.Error(err),
			)
			continue
		}

		s.watchedDirectories[directoryPath] =
			struct{}{}
	}

	for directoryPath := range s.watchedDirectories {
		if _, stillRequired :=
			requiredDirectories[directoryPath]; stillRequired {
			continue
		}

		if removeErr := s.watcher.Remove(
			directoryPath,
		); removeErr != nil &&
			!errors.Is(
				removeErr,
				fsnotify.ErrNonExistentWatch,
			) {
			s.logger.Warn(
				"Failed to remove Canary directory watcher",
				zap.String(
					"directory",
					directoryPath,
				),
				zap.Error(removeErr),
			)
		}

		delete(
			s.watchedDirectories,
			directoryPath,
		)
	}

	s.targets = newTargets

	return nil
}

func (s *FileMonitorService) shouldDebounceEvent(
	key string,
	eventTime time.Time,
) bool {
	s.debounceMutex.Lock()
	defer s.debounceMutex.Unlock()

	previousTime, exists := s.recentEvents[key]
	if exists &&
		eventTime.Sub(previousTime) <
			defaultFileMonitorDebounceWindow {
		return true
	}

	s.recentEvents[key] = eventTime

	return false
}

func (s *FileMonitorService) removeExpiredDebounceEntries() {
	cutoff := time.Now().UTC().Add(
		-5 * defaultFileMonitorDebounceWindow,
	)

	s.debounceMutex.Lock()
	defer s.debounceMutex.Unlock()

	for key, eventTime := range s.recentEvents {
		if eventTime.Before(cutoff) {
			delete(s.recentEvents, key)
		}
	}
}

func classifyFilesystemEvent(
	operation fsnotify.Op,
) (string, string, bool) {
	switch {
	case operation&fsnotify.Remove != 0:
		return EventTypeDeleted,
			CanaryStatusMissing,
			true

	case operation&fsnotify.Rename != 0:
		return EventTypeRenamed,
			CanaryStatusMissing,
			true

	case operation&fsnotify.Write != 0:
		return EventTypeModified,
			CanaryStatusTampered,
			true

	case operation&fsnotify.Create != 0:
		return EventTypeCreated,
			CanaryStatusTriggered,
			true

	case operation&fsnotify.Chmod != 0:
		return EventTypePermissionChanged,
			CanaryStatusTampered,
			true

	default:
		return "", "", false
	}
}

func fileEventCollectorForRuntime() string {
	switch runtime.GOOS {
	case "windows":
		return FileEventCollectorWindowsWatcher

	case "linux":
		return FileEventCollectorLinuxInotify

	case "darwin":
		return FileEventCollectorMacOSFSEvents

	default:
		return FileEventCollectorAgent
	}
}

func normalizeMonitoredFilePath(
	value string,
) string {
	value = filepath.Clean(
		strings.TrimSpace(value),
	)

	if value == "." || value == "" {
		return ""
	}

	if runtime.GOOS == "windows" {
		value = strings.ToLower(value)
	}

	return value
}

func fileMonitorUUIDString(
	value *uuid.UUID,
) *string {
	if value == nil ||
		*value == uuid.Nil {
		return nil
	}

	stringValue := value.String()

	return &stringValue
}

func fileMonitorRequiredUUIDString(
	value uuid.UUID,
) *string {
	if value == uuid.Nil {
		return nil
	}

	stringValue := value.String()

	return &stringValue
}

func fileMonitorStringPointer(
	value string,
) *string {
	return &value
}

func fileMonitorOptionalStringPointer(
	value string,
) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	return &value
}

// SetThreatWorker connects the Threat Engine worker lifecycle to the file
// monitoring runtime. It must be called before Start.
func (s *FileMonitorService) SetThreatWorker(
	worker *ThreatWorker,
) error {
	if s == nil {
		return errors.New(
			"file monitor service is unavailable",
		)
	}

	if worker == nil {
		return errors.New(
			"threat worker is required",
		)
	}

	s.stateMutex.Lock()
	defer s.stateMutex.Unlock()

	if s.started {
		return ErrFileMonitorAlreadyStarted
	}

	if s.threatWorker != nil &&
		s.threatWorker != worker {
		return ErrFileMonitorRuntimeConfigured
	}

	s.threatWorker = worker

	return nil
}
