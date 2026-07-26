package adaptivedeception

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidCanaryInteractionInput = errors.New(
	"invalid canary interaction input",
)

const canaryFingerprintVersion = "1.0.0"

// CanaryInteractionInput contains normalized source information
// collected from a canary access log or file event.
type CanaryInteractionInput struct {
	OrganizationID uuid.UUID
	CanaryFileID   uuid.UUID

	AccessLogID *uuid.UUID
	FileEventID *uuid.UUID

	EventType string

	DeviceIdentifier *string
	DeviceName       *string

	OperatingSystem     *string
	OperatingSystemUser *string

	ProcessName       *string
	ProcessPath       *string
	ProcessID         *int64
	ParentProcessName *string

	SourceIP *string

	IsSuspicious        bool
	RansomwareSuspected bool

	OccurredAt time.Time
}

type canonicalFingerprintPayload struct {
	OrganizationID string `json:"organization_id"`
	CanaryFileID   string `json:"canary_file_id"`

	EventType string `json:"event_type"`

	DeviceIdentifier string `json:"device_identifier"`
	DeviceName       string `json:"device_name"`

	OperatingSystem     string `json:"operating_system"`
	OperatingSystemUser string `json:"operating_system_user"`

	ProcessName       string `json:"process_name"`
	ProcessPath       string `json:"process_path"`
	ProcessID         int64  `json:"process_id"`
	ParentProcessName string `json:"parent_process_name"`

	SourceIP string `json:"source_ip"`
}

// BuildCanaryInteractionFingerprint creates a deterministic
// SHA-256 fingerprint. Source record IDs and timestamps are
// intentionally excluded so repeated behaviour produces the
// same fingerprint and increments occurrence_count.
func BuildCanaryInteractionFingerprint(
	input CanaryInteractionInput,
) (*CanaryInteractionFingerprint, error) {
	if input.OrganizationID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: organization ID is required",
			ErrInvalidCanaryInteractionInput,
		)
	}

	if input.CanaryFileID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: canary file ID is required",
			ErrInvalidCanaryInteractionInput,
		)
	}

	input.AccessLogID =
		normalizeFingerprintUUIDPointer(
			input.AccessLogID,
		)

	input.FileEventID =
		normalizeFingerprintUUIDPointer(
			input.FileEventID,
		)

	if input.AccessLogID == nil &&
		input.FileEventID == nil {
		return nil, fmt.Errorf(
			"%w: access log ID or file event ID is required",
			ErrInvalidCanaryInteractionInput,
		)
	}

	eventType := NormalizeConstant(
		input.EventType,
	)
	if eventType == "" {
		return nil, fmt.Errorf(
			"%w: event type is required",
			ErrInvalidCanaryInteractionInput,
		)
	}

	if input.ProcessID != nil &&
		*input.ProcessID < 0 {
		return nil, fmt.Errorf(
			"%w: process ID cannot be negative",
			ErrInvalidCanaryInteractionInput,
		)
	}

	occurredAt := input.OccurredAt.UTC()
	if occurredAt.IsZero() {
		return nil, fmt.Errorf(
			"%w: occurred time is required",
			ErrInvalidCanaryInteractionInput,
		)
	}

	deviceIdentifier :=
		trimFingerprintStringPointer(
			input.DeviceIdentifier,
		)

	deviceName :=
		trimFingerprintStringPointer(
			input.DeviceName,
		)

	operatingSystem :=
		trimFingerprintStringPointer(
			input.OperatingSystem,
		)

	operatingSystemUser :=
		trimFingerprintStringPointer(
			input.OperatingSystemUser,
		)

	processName :=
		trimFingerprintStringPointer(
			input.ProcessName,
		)

	processPath :=
		trimFingerprintStringPointer(
			input.ProcessPath,
		)

	parentProcessName :=
		trimFingerprintStringPointer(
			input.ParentProcessName,
		)

	sourceIP, err :=
		normalizeFingerprintIPAddress(
			input.SourceIP,
		)
	if err != nil {
		return nil, err
	}

	processIDValue := int64(0)
	if input.ProcessID != nil {
		processIDValue = *input.ProcessID
	}

	payload := canonicalFingerprintPayload{
		OrganizationID: input.OrganizationID.String(),
		CanaryFileID:   input.CanaryFileID.String(),

		EventType: eventType,

		DeviceIdentifier: normalizedFingerprintValue(
			deviceIdentifier,
		),

		DeviceName: normalizedFingerprintValue(
			deviceName,
		),

		OperatingSystem: normalizedFingerprintValue(
			operatingSystem,
		),

		OperatingSystemUser: normalizedFingerprintValue(
			operatingSystemUser,
		),

		ProcessName: normalizedFingerprintValue(
			processName,
		),

		ProcessPath: normalizedFingerprintPath(
			processPath,
		),

		ProcessID: processIDValue,

		ParentProcessName: normalizedFingerprintValue(
			parentProcessName,
		),

		SourceIP: normalizedFingerprintValue(
			sourceIP,
		),
	}

	serializedPayload, err := json.Marshal(
		payload,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode canonical canary interaction: %w",
			err,
		)
	}

	hashValue := sha256.Sum256(
		serializedPayload,
	)

	fingerprintHash := hex.EncodeToString(
		hashValue[:],
	)

	interactionPattern := map[string]any{
		"fingerprint_version": canaryFingerprintVersion,
		"event_type":          eventType,
		"source_kind": resolveFingerprintSourceKind(
			input.AccessLogID,
			input.FileEventID,
		),
		"is_suspicious": input.IsSuspicious,
		"ransomware_suspected": input.
			RansomwareSuspected,
	}

	addFingerprintPatternValue(
		interactionPattern,
		"device_identifier",
		deviceIdentifier,
	)

	addFingerprintPatternValue(
		interactionPattern,
		"device_name",
		deviceName,
	)

	addFingerprintPatternValue(
		interactionPattern,
		"operating_system",
		operatingSystem,
	)

	addFingerprintPatternValue(
		interactionPattern,
		"operating_system_user",
		operatingSystemUser,
	)

	addFingerprintPatternValue(
		interactionPattern,
		"process_name",
		processName,
	)

	addFingerprintPatternValue(
		interactionPattern,
		"process_path",
		processPath,
	)

	addFingerprintPatternValue(
		interactionPattern,
		"parent_process_name",
		parentProcessName,
	)

	addFingerprintPatternValue(
		interactionPattern,
		"source_ip",
		sourceIP,
	)

	if input.ProcessID != nil {
		interactionPattern["process_id"] =
			*input.ProcessID
	}

	return &CanaryInteractionFingerprint{
		ID: uuid.New(),

		OrganizationID: input.OrganizationID,
		CanaryFileID:   input.CanaryFileID,

		AccessLogID: input.AccessLogID,
		FileEventID: input.FileEventID,

		FingerprintHash: fingerprintHash,

		FingerprintVersion: canaryFingerprintVersion,

		EventType: eventType,

		DeviceIdentifier: deviceIdentifier,
		DeviceName:       deviceName,

		OperatingSystem: operatingSystem,

		OperatingSystemUser: operatingSystemUser,

		ProcessName: processName,
		ProcessPath: processPath,
		ProcessID:   input.ProcessID,

		ParentProcessName: parentProcessName,

		SourceIP: sourceIP,

		InteractionPattern: interactionPattern,

		BehaviouralScore: 0,
		ConfidenceScore:  0,

		IsSuspicious: input.IsSuspicious,

		RansomwareSuspected: input.
			RansomwareSuspected,

		OccurrenceCount: 1,

		FirstObservedAt: occurredAt,
		LastObservedAt:  occurredAt,

		CreatedAt: occurredAt,
		UpdatedAt: occurredAt,
	}, nil
}

func normalizeFingerprintUUIDPointer(
	value *uuid.UUID,
) *uuid.UUID {
	if value == nil ||
		*value == uuid.Nil {
		return nil
	}

	normalized := *value

	return &normalized
}

func trimFingerprintStringPointer(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	trimmed := strings.TrimSpace(
		*value,
	)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}

func normalizeFingerprintIPAddress(
	value *string,
) (*string, error) {
	value = trimFingerprintStringPointer(
		value,
	)
	if value == nil {
		return nil, nil
	}

	parsedAddress := net.ParseIP(
		*value,
	)
	if parsedAddress == nil {
		return nil, fmt.Errorf(
			"%w: source IP address is invalid",
			ErrInvalidCanaryInteractionInput,
		)
	}

	normalized := parsedAddress.String()

	return &normalized, nil
}

func normalizedFingerprintValue(
	value *string,
) string {
	if value == nil {
		return ""
	}

	return strings.ToLower(
		strings.TrimSpace(*value),
	)
}

func normalizedFingerprintPath(
	value *string,
) string {
	normalized := normalizedFingerprintValue(
		value,
	)

	return strings.ReplaceAll(
		normalized,
		`\`,
		"/",
	)
}

func resolveFingerprintSourceKind(
	accessLogID *uuid.UUID,
	fileEventID *uuid.UUID,
) string {
	switch {
	case accessLogID != nil &&
		fileEventID != nil:
		return "ACCESS_LOG_AND_FILE_EVENT"

	case accessLogID != nil:
		return "ACCESS_LOG"

	default:
		return "FILE_EVENT"
	}
}

func addFingerprintPatternValue(
	pattern map[string]any,
	key string,
	value *string,
) {
	if value == nil {
		return
	}

	pattern[key] = *value
}
