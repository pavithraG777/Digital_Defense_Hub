package honeytoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

var ErrInvalidFileEventForThreat = errors.New(
	"invalid file event for threat analysis",
)

// ThreatSignalFromFileEvent converts a persisted file event into the
// normalized signal required by the Threat Engine.
func ThreatSignalFromFileEvent(
	event *FileEvent,
) (ThreatSignal, error) {
	if event == nil {
		return ThreatSignal{}, fmt.Errorf(
			"%w: file event is required",
			ErrInvalidFileEventForThreat,
		)
	}

	if event.ID == uuid.Nil {
		return ThreatSignal{}, fmt.Errorf(
			"%w: file event ID is required",
			ErrInvalidFileEventForThreat,
		)
	}

	if event.OrganizationID == uuid.Nil {
		return ThreatSignal{}, fmt.Errorf(
			"%w: organization ID is required",
			ErrInvalidFileEventForThreat,
		)
	}

	eventType := strings.ToUpper(
		strings.TrimSpace(event.EventType),
	)
	if eventType == "" {
		return ThreatSignal{}, fmt.Errorf(
			"%w: event type is required",
			ErrInvalidFileEventForThreat,
		)
	}

	detectionMethod := strings.ToUpper(
		strings.TrimSpace(event.DetectionMethod),
	)
	if detectionMethod == "" {
		detectionMethod = "RULE_BASED"
	}

	resourceType := determineThreatResourceType(event)

	metadata, err := buildFileEventThreatMetadata(event)
	if err != nil {
		return ThreatSignal{}, err
	}

	occurredAt := event.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = event.ReceivedAt
	}
	if occurredAt.IsZero() {
		occurredAt = event.CreatedAt
	}

	return ThreatSignal{
		FileEventID:       event.ID,
		OrganizationID:    event.OrganizationID,
		DepartmentID:      event.DepartmentID,
		MonitoringRuleID:  event.MonitoringRuleID,
		ProtectedFileID:   event.ProtectedFileID,
		HoneytokenID:      event.HoneytokenID,
		CanaryFileID:      event.CanaryFileID,
		ResourceType:      resourceType,
		EventType:         eventType,
		DetectionMethod:   detectionMethod,
		OccurredAt:        occurredAt,
		PreliminaryScore:  event.ThreatScore,
		Suspicious:        event.IsSuspicious,
		AffectedFileCount: 1,
		ProcessName:       normalizeFileEventThreatText(event.ProcessName),
		ProcessID:         event.ProcessID,
		ProcessPath: normalizeFileEventThreatText(
			event.ExecutablePath,
		),
		DeviceName: normalizeFileEventThreatText(
			event.DeviceName,
		),
		DeviceIdentifier: normalizeFileEventThreatText(
			event.DeviceIdentifier,
		),
		SourceIPAddress: normalizeFileEventThreatText(
			event.IPAddress,
		),
		OriginalPath: normalizeFileEventThreatText(
			event.PreviousFilePath,
		),
		CurrentPath: fileEventThreatStringPointer(
			event.FilePath,
		),
		PreviousHash: normalizeFileEventThreatText(
			event.PreviousHash,
		),
		CurrentHash: normalizeFileEventThreatText(
			event.CurrentHash,
		),
		Metadata: metadata,
	}, nil
}

// SubmitFileEvent validates, converts, and queues a file event for background
// Threat Engine processing.
func (w *ThreatWorker) SubmitFileEvent(
	ctx context.Context,
	event *FileEvent,
) error {
	signal, err := ThreatSignalFromFileEvent(event)
	if err != nil {
		return err
	}

	return w.Submit(ctx, signal)
}

// TrySubmitFileEvent performs non-blocking file-event submission.
func (w *ThreatWorker) TrySubmitFileEvent(
	event *FileEvent,
) bool {
	signal, err := ThreatSignalFromFileEvent(event)
	if err != nil {
		if w != nil && w.logger != nil {
			w.logger.Warn(
				"Invalid file event rejected by Threat Engine",
			)
		}

		return false
	}

	return w.TrySubmit(signal)
}

func determineThreatResourceType(event *FileEvent) string {
	sourceType := strings.ToUpper(
		strings.TrimSpace(event.SourceType),
	)

	// The event collector's declared source is authoritative. A Canary may
	// contain a Honeytoken, but a filesystem change is still a Canary event.
	switch sourceType {
	case FileEventSourceCanaryFile:
		return "CANARY_FILE"

	case FileEventSourceHoneytoken:
		return "HONEYTOKEN"

	case FileEventSourceProtectedFile:
		return "PROTECTED_FILE"

	case FileEventSourceUnmanagedFile:
		return "UNMANAGED_FILE"
	}

	// References are used only as a fallback for legacy or imported events.
	switch {
	case event.CanaryFileID != nil:
		return "CANARY_FILE"

	case event.HoneytokenID != nil:
		return "HONEYTOKEN"

	case event.ProtectedFileID != nil:
		return "PROTECTED_FILE"

	default:
		return "FILE_SYSTEM"
	}
}

func buildFileEventThreatMetadata(
	event *FileEvent,
) (json.RawMessage, error) {
	metadata := map[string]any{
		"event_code":          event.EventCode,
		"event_sequence":      event.EventSequence,
		"source_type":         event.SourceType,
		"event_source":        event.EventSource,
		"file_name":           event.FileName,
		"file_extension":      event.FileExtension,
		"mime_type":           event.MimeType,
		"file_size_before":    event.FileSizeBefore,
		"file_size_after":     event.FileSizeAfter,
		"hash_algorithm":      event.HashAlgorithm,
		"process_hash":        event.ProcessHash,
		"parent_process_id":   event.ParentProcessID,
		"parent_process_name": event.ParentProcessName,
		"system_username":     event.SystemUsername,
		"application_user_id": event.ApplicationUserID,
		"evidence_hash":       event.EvidenceHash,
		"severity":            event.Severity,
		"received_at":         event.ReceivedAt,
	}

	if len(event.Metadata) > 0 &&
		json.Valid(event.Metadata) {
		metadata["event_metadata"] = event.Metadata
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf(
			"encode file event threat metadata: %w",
			err,
		)
	}

	return encoded, nil
}

func normalizeFileEventThreatText(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	normalized := strings.TrimSpace(*value)
	if normalized == "" {
		return nil
	}

	return &normalized
}

func fileEventThreatStringPointer(
	value string,
) *string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return nil
	}

	return &normalized
}
