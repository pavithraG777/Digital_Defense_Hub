package honeytoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidFileEventRequest          = errors.New("invalid file event request")
	ErrFileEventFutureTimestamp         = errors.New("file event timestamp is in the future")
	ErrFileEventSourceReferenceRequired = errors.New("file event source reference is required")
	ErrFileEventSourceReferenceMismatch = errors.New("file event source reference does not match source type")
	ErrInvalidFileEventHash             = errors.New("invalid file event hash")
	ErrInvalidFileEventJSON             = errors.New("invalid file event JSON")
	ErrInvalidFileEventIPAddress        = errors.New("invalid file event IP address")
	ErrInvalidFileEventMACAddress       = errors.New("invalid file event MAC address")
)

// FileEventAnalysisSubmitter submits persisted file events
// to another asynchronous analysis engine.
type FileEventAnalysisSubmitter interface {
	TrySubmitFileEventAnalysis(
		organizationID uuid.UUID,
		fileEventID uuid.UUID,
	) bool
}

type FileEventService struct {
	repository *Repository

	threatWorkerMu sync.RWMutex
	threatWorker   *ThreatWorker

	preEncryptionWorkerMu sync.RWMutex
	preEncryptionWorker   FileEventAnalysisSubmitter

	fingerprintWorkerMu sync.RWMutex
	fingerprintWorker   FileEventAnalysisSubmitter
}

// SetThreatWorker connects persisted file events to the asynchronous Threat
// Engine. It must be configured before the API server begins accepting
// requests.
func (s *FileEventService) SetThreatWorker(
	worker *ThreatWorker,
) error {
	if s == nil {
		return errors.New(
			"file event service is unavailable",
		)
	}

	if worker == nil {
		return errors.New(
			"threat worker is required",
		)
	}

	s.threatWorkerMu.Lock()
	defer s.threatWorkerMu.Unlock()

	if s.threatWorker != nil &&
		s.threatWorker != worker {
		return errors.New(
			"threat worker is already configured",
		)
	}

	s.threatWorker = worker

	return nil
}

// SetFingerprintWorker connects persisted CANARY_FILE events
// to the Adaptive Deception fingerprint worker.
func (s *FileMonitorService) SetFingerprintWorker(
	worker FileEventAnalysisSubmitter,
) error {
	if s == nil ||
		s.fileEventService == nil {
		return errors.New(
			"file monitor service is unavailable",
		)
	}

	if worker == nil {
		return errors.New(
			"canary fingerprint worker is required",
		)
	}

	return s.fileEventService.SetFingerprintWorker(
		worker,
	)
}

// SetPreEncryptionWorker connects persisted file events to the asynchronous
// Pre-Encryption Ransomware Detection worker.
func (s *FileEventService) SetPreEncryptionWorker(
	worker FileEventAnalysisSubmitter,
) error {
	if s == nil {
		return errors.New(
			"file event service is unavailable",
		)
	}

	if worker == nil {
		return errors.New(
			"pre-encryption worker is required",
		)
	}

	s.preEncryptionWorkerMu.Lock()
	defer s.preEncryptionWorkerMu.Unlock()

	if s.preEncryptionWorker != nil {
		return errors.New(
			"pre-encryption worker is already configured",
		)
	}

	s.preEncryptionWorker = worker

	return nil
}

// SetFingerprintWorker connects persisted CANARY_FILE events
// to the Adaptive Deception fingerprint worker.
func (s *FileEventService) SetFingerprintWorker(
	worker FileEventAnalysisSubmitter,
) error {
	if s == nil {
		return errors.New(
			"file event service is unavailable",
		)
	}

	if worker == nil {
		return errors.New(
			"canary fingerprint worker is required",
		)
	}

	s.fingerprintWorkerMu.Lock()
	defer s.fingerprintWorkerMu.Unlock()

	if s.fingerprintWorker != nil {
		return errors.New(
			"canary fingerprint worker is already configured",
		)
	}

	s.fingerprintWorker = worker

	return nil
}

func (s *FileEventService) submitFileEventForThreatAnalysis(
	event *FileEvent,
) {
	if s == nil || event == nil {
		return
	}

	s.threatWorkerMu.RLock()
	worker := s.threatWorker
	s.threatWorkerMu.RUnlock()

	if worker == nil {
		return
	}

	worker.TrySubmitFileEvent(event)
}

func (s *FileEventService) submitFileEventForPreEncryptionAnalysis(
	event *FileEvent,
) {
	if s == nil ||
		event == nil ||
		event.ID == uuid.Nil ||
		event.OrganizationID == uuid.Nil {
		return
	}

	s.preEncryptionWorkerMu.RLock()
	worker := s.preEncryptionWorker
	s.preEncryptionWorkerMu.RUnlock()

	if worker == nil {
		return
	}

	worker.TrySubmitFileEventAnalysis(
		event.OrganizationID,
		event.ID,
	)
}

func (s *FileEventService) submitFileEventForFingerprintAnalysis(
	event *FileEvent,
) {
	if s == nil ||
		event == nil ||
		event.ID == uuid.Nil ||
		event.OrganizationID == uuid.Nil ||
		event.CanaryFileID == nil {
		return
	}

	s.fingerprintWorkerMu.RLock()
	worker := s.fingerprintWorker
	s.fingerprintWorkerMu.RUnlock()

	if worker == nil {
		return
	}

	worker.TrySubmitFileEventAnalysis(
		event.OrganizationID,
		event.ID,
	)
}
func NewFileEventService(
	repository *Repository,
) (*FileEventService, error) {
	if repository == nil {
		return nil, errors.New(
			"file event repository is required",
		)
	}

	return &FileEventService{
		repository: repository,
	}, nil
}

func (s *FileEventService) CreateFileEvent(
	ctx context.Context,
	organizationID uuid.UUID,
	applicationUserID *uuid.UUID,
	ipAddress string,
	request CreateFileEventRequest,
) (*CreateFileEventResponse, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	request.SourceType = strings.ToUpper(
		strings.TrimSpace(request.SourceType),
	)
	request.EventType = strings.ToUpper(
		strings.TrimSpace(request.EventType),
	)
	request.EventSource = strings.ToUpper(
		strings.TrimSpace(request.EventSource),
	)
	request.FileName = strings.TrimSpace(
		request.FileName,
	)
	request.FilePath = strings.TrimSpace(
		request.FilePath,
	)

	if request.FileName == "" ||
		request.FilePath == "" {
		return nil, ErrInvalidFileEventRequest
	}

	if !isSupportedFileEventSourceType(
		request.SourceType,
	) {
		return nil, ErrInvalidFileEventRequest
	}

	if !isSupportedFileEventType(
		request.EventType,
	) {
		return nil, ErrInvalidFileEventRequest
	}

	if !isSupportedFileEventCollector(
		request.EventSource,
	) {
		return nil, ErrInvalidFileEventRequest
	}

	detectionMethod := DetectionMethodRuleBased

	if request.DetectionMethod != nil {
		detectionMethod = strings.ToUpper(
			strings.TrimSpace(
				*request.DetectionMethod,
			),
		)
	}

	if !isSupportedDetectionMethod(
		detectionMethod,
	) {
		return nil, ErrInvalidFileEventRequest
	}

	departmentID, err := parseFileEventOptionalUUID(
		request.DepartmentID,
		"department ID",
	)
	if err != nil {
		return nil, err
	}

	monitoringRuleID, err :=
		parseFileEventOptionalUUID(
			request.MonitoringRuleID,
			"monitoring rule ID",
		)
	if err != nil {
		return nil, err
	}

	protectedFileID, err :=
		parseFileEventOptionalUUID(
			request.ProtectedFileID,
			"protected file ID",
		)
	if err != nil {
		return nil, err
	}

	honeytokenID, err :=
		parseFileEventOptionalUUID(
			request.HoneytokenID,
			"honeytoken ID",
		)
	if err != nil {
		return nil, err
	}

	canaryFileID, err :=
		parseFileEventOptionalUUID(
			request.CanaryFileID,
			"canary file ID",
		)
	if err != nil {
		return nil, err
	}

	if err = validateFileEventSourceReferences(
		request.SourceType,
		protectedFileID,
		honeytokenID,
		canaryFileID,
	); err != nil {
		return nil, err
	}

	occurredAt, err := parseFileEventOccurredAt(
		request.OccurredAt,
	)
	if err != nil {
		return nil, err
	}

	hashAlgorithm := CanaryHashAlgorithmSHA256

	if request.HashAlgorithm != nil {
		hashAlgorithm = strings.ToUpper(
			strings.TrimSpace(
				*request.HashAlgorithm,
			),
		)
	}

	if err = validateFileEventHashes(
		hashAlgorithm,
		request.PreviousHash,
		request.CurrentHash,
	); err != nil {
		return nil, err
	}

	rawEvent, err := normalizeFileEventJSON(
		request.RawEvent,
		false,
	)
	if err != nil {
		return nil, err
	}

	metadata, err := normalizeFileEventJSON(
		request.Metadata,
		true,
	)
	if err != nil {
		return nil, err
	}

	normalizedIPAddress, err :=
		normalizeFileEventIPAddress(ipAddress)
	if err != nil {
		return nil, err
	}

	normalizedMACAddress, err :=
		normalizeFileEventMACAddress(
			request.MACAddress,
		)
	if err != nil {
		return nil, err
	}

	applicationUserID, err =
		normalizeFileEventApplicationUserID(
			applicationUserID,
		)
	if err != nil {
		return nil, err
	}

	if err = s.repository.ValidateFileEventRelations(
		ctx,
		organizationID,
		departmentID,
		monitoringRuleID,
		protectedFileID,
		honeytokenID,
		canaryFileID,
		applicationUserID,
	); err != nil {
		return nil, err
	}

	severity, threatScore, suspicious :=
		assessPreliminaryFileEvent(
			request.SourceType,
			request.EventType,
		)

	filePath := normalizeFileEventPath(
		request.FilePath,
	)
	previousFilePath := normalizeFileEventOptionalPath(
		request.PreviousFilePath,
	)

	eventFingerprint := buildFileEventFingerprint(
		organizationID,
		request.SourceType,
		request.EventType,
		filePath,
		previousFilePath,
		request.CurrentHash,
		request.ProcessID,
		request.DeviceIdentifier,
		occurredAt,
	)

	event := &FileEvent{
		OrganizationID:    organizationID,
		DepartmentID:      departmentID,
		MonitoringRuleID:  monitoringRuleID,
		ProtectedFileID:   protectedFileID,
		HoneytokenID:      honeytokenID,
		CanaryFileID:      canaryFileID,
		EventFingerprint:  eventFingerprint,
		SourceType:        request.SourceType,
		EventType:         request.EventType,
		EventSource:       request.EventSource,
		DetectionMethod:   detectionMethod,
		FileName:          request.FileName,
		FilePath:          filePath,
		PreviousFilePath:  previousFilePath,
		FileExtension:     normalizeFileEventOptionalString(request.FileExtension),
		MimeType:          normalizeFileEventOptionalString(request.MimeType),
		FileSizeBefore:    request.FileSizeBefore,
		FileSizeAfter:     request.FileSizeAfter,
		PreviousHash:      normalizeFileEventHash(request.PreviousHash),
		CurrentHash:       normalizeFileEventHash(request.CurrentHash),
		HashAlgorithm:     hashAlgorithm,
		ProcessID:         request.ProcessID,
		ProcessName:       normalizeFileEventOptionalString(request.ProcessName),
		ExecutablePath:    normalizeFileEventOptionalString(request.ExecutablePath),
		ParentProcessID:   request.ParentProcessID,
		ParentProcessName: normalizeFileEventOptionalString(request.ParentProcessName),
		CommandLine:       normalizeFileEventOptionalString(request.CommandLine),
		ProcessHash:       normalizeFileEventHash(request.ProcessHash),
		SystemUsername:    normalizeFileEventOptionalString(request.SystemUsername),
		ApplicationUserID: applicationUserID,
		DeviceName:        normalizeFileEventOptionalString(request.DeviceName),
		DeviceIdentifier:  normalizeFileEventOptionalString(request.DeviceIdentifier),
		IPAddress:         normalizedIPAddress,
		MACAddress:        normalizedMACAddress,
		Severity:          severity,
		ThreatScore:       threatScore,
		IsSuspicious:      suspicious,
		Status:            FileEventStatusReceived,
		ProcessingError:   nil,
		EvidenceCopyPath:  nil,
		EvidenceHash:      nil,
		RawEvent:          rawEvent,
		Metadata:          metadata,
		OccurredAt:        occurredAt,
		ProcessedAt:       nil,
	}

	const maximumCodeGenerationAttempts = 3

	for attempt := 0; attempt <
		maximumCodeGenerationAttempts; attempt++ {
		event.ID = uuid.New()
		event.EventCode = generateFileEventCode(
			event.ID,
		)

		err = s.repository.CreateFileEvent(
			ctx,
			event,
		)
		if err == nil {
			s.submitFileEventForThreatAnalysis(event)

			s.submitFileEventForPreEncryptionAnalysis(
				event,
			)

			s.submitFileEventForFingerprintAnalysis(
				event,
			)

			return buildCreateFileEventResponse(
				event,
			), nil
		}

		if errors.Is(err, ErrFileEventDuplicate) {
			existingEvent, findErr :=
				s.repository.FindFileEventByFingerprint(
					ctx,
					organizationID,
					eventFingerprint,
				)
			if findErr != nil {
				return nil, findErr
			}

			return buildCreateFileEventResponse(
				existingEvent,
			), nil
		}

		if !errors.Is(err, ErrFileEventCodeExists) {
			return nil, err
		}
	}

	return nil, ErrFileEventCodeExists
}

func (s *FileEventService) GetFileEvent(
	ctx context.Context,
	organizationID uuid.UUID,
	eventID string,
) (*GetFileEventResponse, error) {
	parsedEventID, err := parseFileEventRequiredUUID(
		eventID,
		"file event ID",
	)
	if err != nil {
		return nil, err
	}

	event, err := s.repository.FindFileEventByID(
		ctx,
		organizationID,
		parsedEventID,
	)
	if err != nil {
		return nil, err
	}

	response := buildGetFileEventResponse(event)

	return &response, nil
}

func (s *FileEventService) ListFileEvents(
	ctx context.Context,
	organizationID uuid.UUID,
	request ListFileEventsRequest,
) (*ListFileEventsResponse, error) {
	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	departmentID, err := parseFileEventOptionalUUID(
		request.DepartmentID,
		"department ID",
	)
	if err != nil {
		return nil, err
	}

	sourceType := strings.ToUpper(
		strings.TrimSpace(request.SourceType),
	)
	eventType := strings.ToUpper(
		strings.TrimSpace(request.EventType),
	)
	severity := strings.ToUpper(
		strings.TrimSpace(request.Severity),
	)
	status := strings.ToUpper(
		strings.TrimSpace(request.Status),
	)

	if sourceType != "" &&
		!isSupportedFileEventSourceType(sourceType) {
		return nil, ErrInvalidFileEventRequest
	}

	if eventType != "" &&
		!isSupportedFileEventType(eventType) {
		return nil, ErrInvalidFileEventRequest
	}

	if severity != "" &&
		!isSupportedFileEventSeverity(severity) {
		return nil, ErrInvalidFileEventRequest
	}

	if status != "" &&
		!isSupportedFileEventStatus(status) {
		return nil, ErrInvalidFileEventRequest
	}

	from, err := parseFileEventFilterTime(
		request.From,
		"from",
	)
	if err != nil {
		return nil, err
	}

	to, err := parseFileEventFilterTime(
		request.To,
		"to",
	)
	if err != nil {
		return nil, err
	}

	if from != nil &&
		to != nil &&
		to.Before(*from) {
		return nil, fmt.Errorf(
			"%w: to must not be before from",
			ErrInvalidFileEventRequest,
		)
	}

	page := request.Page
	if page <= 0 {
		page = 1
	}

	pageSize := request.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}

	if pageSize > 100 {
		pageSize = 100
	}

	events, total, err :=
		s.repository.ListFileEvents(
			ctx,
			FileEventListFilter{
				OrganizationID: organizationID,
				DepartmentID:   departmentID,
				SourceType:     sourceType,
				EventType:      eventType,
				Severity:       severity,
				Status:         status,
				IsSuspicious:   request.IsSuspicious,
				From:           from,
				To:             to,
				Limit:          pageSize,
				Offset:         (page - 1) * pageSize,
			},
		)
	if err != nil {
		return nil, err
	}

	items := make(
		[]GetFileEventResponse,
		0,
		len(events),
	)

	for index := range events {
		items = append(
			items,
			buildGetFileEventResponse(&events[index]),
		)
	}

	totalPages := 0

	if total > 0 {
		totalPages = int(
			(total + int64(pageSize) - 1) /
				int64(pageSize),
		)
	}

	return &ListFileEventsResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func buildCreateFileEventResponse(
	event *FileEvent,
) *CreateFileEventResponse {
	return &CreateFileEventResponse{
		ID:            event.ID,
		EventSequence: event.EventSequence,
		EventCode:     event.EventCode,
		SourceType:    event.SourceType,
		EventType:     event.EventType,
		FileName:      event.FileName,
		Severity:      event.Severity,
		ThreatScore:   event.ThreatScore,
		IsSuspicious:  event.IsSuspicious,
		Status:        event.Status,
		OccurredAt:    event.OccurredAt,
		ReceivedAt:    event.ReceivedAt,
	}
}

func buildGetFileEventResponse(
	event *FileEvent,
) GetFileEventResponse {
	return GetFileEventResponse{
		ID:                event.ID,
		EventSequence:     event.EventSequence,
		EventCode:         event.EventCode,
		OrganizationID:    event.OrganizationID,
		DepartmentID:      event.DepartmentID,
		MonitoringRuleID:  event.MonitoringRuleID,
		ProtectedFileID:   event.ProtectedFileID,
		HoneytokenID:      event.HoneytokenID,
		CanaryFileID:      event.CanaryFileID,
		SourceType:        event.SourceType,
		EventType:         event.EventType,
		EventSource:       event.EventSource,
		DetectionMethod:   event.DetectionMethod,
		FileName:          event.FileName,
		FileExtension:     event.FileExtension,
		MimeType:          event.MimeType,
		FileSizeBefore:    event.FileSizeBefore,
		FileSizeAfter:     event.FileSizeAfter,
		PreviousHash:      event.PreviousHash,
		CurrentHash:       event.CurrentHash,
		HashAlgorithm:     event.HashAlgorithm,
		ProcessID:         event.ProcessID,
		ProcessName:       event.ProcessName,
		ParentProcessID:   event.ParentProcessID,
		ParentProcessName: event.ParentProcessName,
		ProcessHash:       event.ProcessHash,
		SystemUsername:    event.SystemUsername,
		DeviceName:        event.DeviceName,
		DeviceIdentifier:  event.DeviceIdentifier,
		Severity:          event.Severity,
		ThreatScore:       event.ThreatScore,
		IsSuspicious:      event.IsSuspicious,
		Status:            event.Status,
		EvidenceHash:      event.EvidenceHash,
		Metadata:          event.Metadata,
		OccurredAt:        event.OccurredAt,
		ReceivedAt:        event.ReceivedAt,
		ProcessedAt:       event.ProcessedAt,
		CreatedAt:         event.CreatedAt,
		UpdatedAt:         event.UpdatedAt,
	}
}

func validateFileEventSourceReferences(
	sourceType string,
	protectedFileID *uuid.UUID,
	honeytokenID *uuid.UUID,
	canaryFileID *uuid.UUID,
) error {
	switch sourceType {
	case FileEventSourceProtectedFile:
		if protectedFileID == nil {
			return ErrFileEventSourceReferenceRequired
		}

		if honeytokenID != nil ||
			canaryFileID != nil {
			return ErrFileEventSourceReferenceMismatch
		}

	case FileEventSourceHoneytoken:
		if honeytokenID == nil {
			return ErrFileEventSourceReferenceRequired
		}

		if protectedFileID != nil ||
			canaryFileID != nil {
			return ErrFileEventSourceReferenceMismatch
		}

	case FileEventSourceCanaryFile:
		if canaryFileID == nil {
			return ErrFileEventSourceReferenceRequired
		}

		if protectedFileID != nil {
			return ErrFileEventSourceReferenceMismatch
		}

	case FileEventSourceUnmanagedFile:
		if protectedFileID != nil ||
			honeytokenID != nil ||
			canaryFileID != nil {
			return ErrFileEventSourceReferenceMismatch
		}

	default:
		return ErrInvalidFileEventRequest
	}

	return nil
}

func assessPreliminaryFileEvent(
	sourceType string,
	eventType string,
) (string, int, bool) {
	if eventType == EventTypeEncrypted ||
		eventType == EventTypeMultipleFileChanges {
		return ThreatLevelCritical, 90, true
	}

	switch sourceType {
	case FileEventSourceHoneytoken:
		return ThreatLevelCritical, 90, true

	case FileEventSourceCanaryFile:
		switch eventType {
		case EventTypeCreated:
			return ThreatLevelHigh, 60, true

		case EventTypeOpened,
			EventTypeRead,
			EventTypeCopied:
			return ThreatLevelHigh, 65, true

		case EventTypeMoved,
			EventTypeRenamed,
			EventTypeModified,
			EventTypeDeleted,
			EventTypeExtensionChanged,
			EventTypePermissionChanged,
			EventTypeHashChanged:
			return ThreatLevelCritical, 85, true

		default:
			return ThreatLevelMedium, 40, true
		}

	case FileEventSourceProtectedFile:
		switch eventType {
		case EventTypeDeleted,
			EventTypeHashChanged,
			EventTypePermissionChanged:
			return ThreatLevelHigh, 60, true

		case EventTypeModified,
			EventTypeRenamed,
			EventTypeExtensionChanged:
			return ThreatLevelMedium, 40, true

		default:
			return ThreatLevelLow, 10, false
		}

	default:
		return ThreatLevelLow, 0, false
	}
}

func buildFileEventFingerprint(
	organizationID uuid.UUID,
	sourceType string,
	eventType string,
	filePath string,
	previousFilePath *string,
	currentHash *string,
	processID *int64,
	deviceIdentifier *string,
	occurredAt time.Time,
) string {
	components := []string{
		organizationID.String(),
		sourceType,
		eventType,
		normalizeFileEventPathForFingerprint(
			filePath,
		),
		fileEventOptionalStringValue(
			previousFilePath,
		),
		fileEventOptionalStringValue(
			normalizeFileEventHash(currentHash),
		),
		fileEventOptionalInt64Value(processID),
		fileEventOptionalStringValue(
			normalizeFileEventOptionalString(
				deviceIdentifier,
			),
		),
		occurredAt.UTC().Format(
			time.RFC3339Nano,
		),
	}

	sum := sha256.Sum256(
		[]byte(strings.Join(components, "|")),
	)

	return hex.EncodeToString(sum[:])
}

func generateFileEventCode(
	eventID uuid.UUID,
) string {
	identifier := strings.ReplaceAll(
		eventID.String(),
		"-",
		"",
	)

	return "FEV-" + strings.ToUpper(identifier)
}

func normalizeFileEventJSON(
	value json.RawMessage,
	requireObject bool,
) (json.RawMessage, error) {
	trimmedValue := bytes.TrimSpace(value)

	if len(trimmedValue) == 0 {
		if requireObject {
			return json.RawMessage(`{}`), nil
		}

		return nil, nil
	}

	if !json.Valid(trimmedValue) {
		return nil, ErrInvalidFileEventJSON
	}

	if requireObject &&
		trimmedValue[0] != '{' {
		return nil, fmt.Errorf(
			"%w: metadata must be a JSON object",
			ErrInvalidFileEventJSON,
		)
	}

	copiedValue := append(
		json.RawMessage(nil),
		trimmedValue...,
	)

	return copiedValue, nil
}

func validateFileEventHashes(
	hashAlgorithm string,
	previousHash *string,
	currentHash *string,
) error {
	var requiredLength int

	switch hashAlgorithm {
	case CanaryHashAlgorithmSHA256:
		requiredLength = 64

	case CanaryHashAlgorithmSHA384:
		requiredLength = 96

	case CanaryHashAlgorithmSHA512:
		requiredLength = 128

	default:
		return ErrInvalidFileEventHash
	}

	for _, value := range []*string{
		previousHash,
		currentHash,
	} {
		if value == nil ||
			strings.TrimSpace(*value) == "" {
			continue
		}

		normalizedHash := strings.ToLower(
			strings.TrimSpace(*value),
		)

		if len(normalizedHash) != requiredLength {
			return ErrInvalidFileEventHash
		}

		if _, err := hex.DecodeString(
			normalizedHash,
		); err != nil {
			return ErrInvalidFileEventHash
		}
	}

	return nil
}

func normalizeFileEventIPAddress(
	ipAddress string,
) (*string, error) {
	ipAddress = strings.TrimSpace(ipAddress)

	if ipAddress == "" {
		return nil, nil
	}

	parsedAddress := net.ParseIP(ipAddress)
	if parsedAddress == nil {
		return nil, ErrInvalidFileEventIPAddress
	}

	normalizedAddress := parsedAddress.String()

	return &normalizedAddress, nil
}

func normalizeFileEventMACAddress(
	macAddress *string,
) (*string, error) {
	if macAddress == nil ||
		strings.TrimSpace(*macAddress) == "" {
		return nil, nil
	}

	parsedAddress, err := net.ParseMAC(
		strings.TrimSpace(*macAddress),
	)
	if err != nil {
		return nil, ErrInvalidFileEventMACAddress
	}

	normalizedAddress := parsedAddress.String()

	return &normalizedAddress, nil
}

func normalizeFileEventApplicationUserID(
	userID *uuid.UUID,
) (*uuid.UUID, error) {
	if userID == nil {
		return nil, nil
	}

	if *userID == uuid.Nil {
		return nil, errors.New(
			"application user ID is invalid",
		)
	}

	normalizedID := *userID

	return &normalizedID, nil
}

func parseFileEventOccurredAt(
	value string,
) (time.Time, error) {
	value = strings.TrimSpace(value)

	occurredAt, err := time.Parse(
		time.RFC3339,
		value,
	)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"%w: occurred_at must use RFC3339 format",
			ErrInvalidFileEventRequest,
		)
	}

	occurredAt = occurredAt.UTC()

	if occurredAt.After(
		time.Now().UTC().Add(5 * time.Minute),
	) {
		return time.Time{}, ErrFileEventFutureTimestamp
	}

	return occurredAt, nil
}

func parseFileEventFilterTime(
	value *string,
	fieldName string,
) (*time.Time, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return nil, nil
	}

	parsedValue, err := time.Parse(
		time.RFC3339,
		strings.TrimSpace(*value),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %s must use RFC3339 format",
			ErrInvalidFileEventRequest,
			fieldName,
		)
	}

	parsedValue = parsedValue.UTC()

	return &parsedValue, nil
}

func parseFileEventRequiredUUID(
	value string,
	fieldName string,
) (uuid.UUID, error) {
	parsedValue, err := uuid.Parse(
		strings.TrimSpace(value),
	)
	if err != nil ||
		parsedValue == uuid.Nil {
		return uuid.Nil, fmt.Errorf(
			"%w: %s must be a valid UUID",
			ErrInvalidFileEventRequest,
			fieldName,
		)
	}

	return parsedValue, nil
}

func parseFileEventOptionalUUID(
	value *string,
	fieldName string,
) (*uuid.UUID, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return nil, nil
	}

	parsedValue, err := uuid.Parse(
		strings.TrimSpace(*value),
	)
	if err != nil ||
		parsedValue == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: %s must be a valid UUID",
			ErrInvalidFileEventRequest,
			fieldName,
		)
	}

	return &parsedValue, nil
}

func normalizeFileEventOptionalString(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	trimmedValue := strings.TrimSpace(*value)
	if trimmedValue == "" {
		return nil
	}

	return &trimmedValue
}

func normalizeFileEventHash(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	normalizedValue := strings.ToLower(
		strings.TrimSpace(*value),
	)
	if normalizedValue == "" {
		return nil
	}

	return &normalizedValue
}

func normalizeFileEventPath(
	value string,
) string {
	return strings.TrimSpace(value)
}

func normalizeFileEventOptionalPath(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	normalizedValue := strings.TrimSpace(*value)
	if normalizedValue == "" {
		return nil
	}

	return &normalizedValue
}

func normalizeFileEventPathForFingerprint(
	value string,
) string {
	value = strings.ReplaceAll(
		strings.TrimSpace(value),
		`\`,
		"/",
	)

	return strings.ToLower(path.Clean(value))
}

func fileEventOptionalStringValue(
	value *string,
) string {
	if value == nil {
		return ""
	}

	return strings.TrimSpace(*value)
}

func fileEventOptionalInt64Value(
	value *int64,
) string {
	if value == nil {
		return ""
	}

	return strconv.FormatInt(*value, 10)
}

func isSupportedFileEventSourceType(
	value string,
) bool {
	switch value {
	case FileEventSourceProtectedFile,
		FileEventSourceHoneytoken,
		FileEventSourceCanaryFile,
		FileEventSourceUnmanagedFile:
		return true

	default:
		return false
	}
}

func isSupportedFileEventType(
	value string,
) bool {
	switch value {
	case EventTypeCreated,
		EventTypeOpened,
		EventTypeRead,
		EventTypeCopied,
		EventTypeMoved,
		EventTypeRenamed,
		EventTypeModified,
		EventTypeEncrypted,
		EventTypeDeleted,
		EventTypeExtensionChanged,
		EventTypePermissionChanged,
		EventTypeHashChanged,
		EventTypeMultipleFileChanges,
		EventTypeCustom:
		return true

	default:
		return false
	}
}

func isSupportedFileEventCollector(
	value string,
) bool {
	switch value {
	case FileEventCollectorWindowsWatcher,
		FileEventCollectorLinuxInotify,
		FileEventCollectorMacOSFSEvents,
		FileEventCollectorAPI,
		FileEventCollectorAgent,
		FileEventCollectorManual,
		FileEventCollectorSystem:
		return true

	default:
		return false
	}
}

func isSupportedDetectionMethod(
	value string,
) bool {
	switch value {
	case DetectionMethodRuleBased,
		DetectionMethodSignatureBased,
		DetectionMethodBehaviourBased,
		DetectionMethodAIBased,
		DetectionMethodHybrid:
		return true

	default:
		return false
	}
}

func isSupportedFileEventSeverity(
	value string,
) bool {
	switch value {
	case ThreatLevelLow,
		ThreatLevelMedium,
		ThreatLevelHigh,
		ThreatLevelCritical:
		return true

	default:
		return false
	}
}

func isSupportedFileEventStatus(
	value string,
) bool {
	switch value {
	case FileEventStatusReceived,
		FileEventStatusQueued,
		FileEventStatusProcessing,
		FileEventStatusProcessed,
		FileEventStatusFailed,
		FileEventStatusIgnored:
		return true

	default:
		return false
	}
}
