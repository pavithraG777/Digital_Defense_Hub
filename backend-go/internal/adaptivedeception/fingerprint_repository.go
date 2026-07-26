package adaptivedeception

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const sha256DigestByteLength = 32

const fingerprintSelectColumns = `
	id,
	fingerprint_sequence,
	organization_id,
	canary_file_id,
	access_log_id,
	file_event_id,
	fingerprint_hash,
	fingerprint_version,
	event_type,
	device_identifier,
	device_name,
	operating_system,
	operating_system_user,
	process_name,
	process_path,
	process_id,
	parent_process_name,
	source_ip::text,
	interaction_pattern,
	behavioural_score,
	confidence_score,
	is_suspicious,
	ransomware_suspected,
	occurrence_count,
	first_observed_at,
	last_observed_at,
	created_at,
	updated_at
`

// UpsertCanaryInteractionFingerprint atomically creates a new
// fingerprint or increments an existing interaction pattern.
func (r *Repository) UpsertCanaryInteractionFingerprint(
	ctx context.Context,
	fingerprint *CanaryInteractionFingerprint,
) (*CanaryInteractionFingerprint, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"adaptive deception repository is unavailable",
		)
	}

	if fingerprint == nil {
		return nil, errors.New(
			"canary interaction fingerprint is required",
		)
	}

	if fingerprint.ID == uuid.Nil {
		fingerprint.ID = uuid.New()
	}

	if fingerprint.OrganizationID == uuid.Nil {
		return nil, errors.New(
			"fingerprint organization ID is required",
		)
	}

	if fingerprint.CanaryFileID == uuid.Nil {
		return nil, errors.New(
			"fingerprint canary file ID is required",
		)
	}

	fingerprint.AccessLogID =
		normalizeFingerprintUUIDPointer(
			fingerprint.AccessLogID,
		)

	fingerprint.FileEventID =
		normalizeFingerprintUUIDPointer(
			fingerprint.FileEventID,
		)

	if fingerprint.AccessLogID == nil &&
		fingerprint.FileEventID == nil {
		return nil, errors.New(
			"fingerprint source reference is required",
		)
	}

	fingerprint.FingerprintHash =
		strings.ToLower(
			strings.TrimSpace(
				fingerprint.FingerprintHash,
			),
		)

	decodedHash, err := hex.DecodeString(
		fingerprint.FingerprintHash,
	)
	if err != nil ||
		len(decodedHash) != sha256DigestByteLength {
		return nil, errors.New(
			"fingerprint hash must be a 64-character SHA-256 value",
		)
	}

	fingerprint.FingerprintVersion =
		strings.TrimSpace(
			fingerprint.FingerprintVersion,
		)

	if fingerprint.FingerprintVersion == "" {
		fingerprint.FingerprintVersion =
			canaryFingerprintVersion
	}

	fingerprint.EventType =
		NormalizeConstant(
			fingerprint.EventType,
		)

	if fingerprint.EventType == "" {
		return nil, errors.New(
			"fingerprint event type is required",
		)
	}

	if fingerprint.ProcessID != nil &&
		*fingerprint.ProcessID < 0 {
		return nil, errors.New(
			"fingerprint process ID cannot be negative",
		)
	}

	if fingerprint.FirstObservedAt.IsZero() {
		return nil, errors.New(
			"fingerprint first observed time is required",
		)
	}

	if fingerprint.LastObservedAt.IsZero() {
		return nil, errors.New(
			"fingerprint last observed time is required",
		)
	}

	fingerprint.FirstObservedAt =
		fingerprint.FirstObservedAt.UTC()

	fingerprint.LastObservedAt =
		fingerprint.LastObservedAt.UTC()

	if fingerprint.LastObservedAt.Before(
		fingerprint.FirstObservedAt,
	) {
		return nil, errors.New(
			"fingerprint last observed time cannot precede first observed time",
		)
	}

	if fingerprint.CreatedAt.IsZero() {
		fingerprint.CreatedAt =
			fingerprint.FirstObservedAt
	} else {
		fingerprint.CreatedAt =
			fingerprint.CreatedAt.UTC()
	}

	if fingerprint.UpdatedAt.IsZero() {
		fingerprint.UpdatedAt =
			fingerprint.LastObservedAt
	} else {
		fingerprint.UpdatedAt =
			fingerprint.UpdatedAt.UTC()
	}

	if fingerprint.OccurrenceCount <= 0 {
		fingerprint.OccurrenceCount = 1
	}

	if fingerprint.InteractionPattern == nil {
		fingerprint.InteractionPattern =
			make(map[string]any)
	}

	if err = validateFingerprintScores(
		fingerprint,
	); err != nil {
		return nil, err
	}

	interactionPatternJSON, err := json.Marshal(
		fingerprint.InteractionPattern,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode canary interaction pattern: %w",
			err,
		)
	}

	const query = `
		INSERT INTO canary_interaction_fingerprints AS existing (
			id,
			organization_id,
			canary_file_id,
			access_log_id,
			file_event_id,
			fingerprint_hash,
			fingerprint_version,
			event_type,
			device_identifier,
			device_name,
			operating_system,
			operating_system_user,
			process_name,
			process_path,
			process_id,
			parent_process_name,
			source_ip,
			interaction_pattern,
			behavioural_score,
			confidence_score,
			is_suspicious,
			ransomware_suspected,
			occurrence_count,
			first_observed_at,
			last_observed_at,
			created_at,
			updated_at
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9,
			$10,
			$11,
			$12,
			$13,
			$14,
			$15,
			$16,
			$17::inet,
			$18::jsonb,
			$19,
			$20,
			$21,
			$22,
			$23,
			$24,
			$25,
			$26,
			$27
		)
		ON CONFLICT (
			organization_id,
			fingerprint_hash
		)
		DO UPDATE SET
			canary_file_id =
				EXCLUDED.canary_file_id,

			access_log_id =
				COALESCE(
					EXCLUDED.access_log_id,
					existing.access_log_id
				),

			file_event_id =
				COALESCE(
					EXCLUDED.file_event_id,
					existing.file_event_id
				),

			device_identifier =
				COALESCE(
					EXCLUDED.device_identifier,
					existing.device_identifier
				),

			device_name =
				COALESCE(
					EXCLUDED.device_name,
					existing.device_name
				),

			operating_system =
				COALESCE(
					EXCLUDED.operating_system,
					existing.operating_system
				),

			operating_system_user =
				COALESCE(
					EXCLUDED.operating_system_user,
					existing.operating_system_user
				),

			process_name =
				COALESCE(
					EXCLUDED.process_name,
					existing.process_name
				),

			process_path =
				COALESCE(
					EXCLUDED.process_path,
					existing.process_path
				),

			process_id =
				COALESCE(
					EXCLUDED.process_id,
					existing.process_id
				),

			parent_process_name =
				COALESCE(
					EXCLUDED.parent_process_name,
					existing.parent_process_name
				),

			source_ip =
				COALESCE(
					EXCLUDED.source_ip,
					existing.source_ip
				),

			interaction_pattern =
				existing.interaction_pattern ||
				EXCLUDED.interaction_pattern,

			behavioural_score =
				GREATEST(
					existing.behavioural_score,
					EXCLUDED.behavioural_score
				),

			confidence_score =
				GREATEST(
					existing.confidence_score,
					EXCLUDED.confidence_score
				),

			is_suspicious =
				existing.is_suspicious OR
				EXCLUDED.is_suspicious,

			ransomware_suspected =
				existing.ransomware_suspected OR
				EXCLUDED.ransomware_suspected,

			occurrence_count =
				existing.occurrence_count +
				CASE
					WHEN (
						EXCLUDED.access_log_id
							IS NOT NULL
						AND existing.access_log_id =
							EXCLUDED.access_log_id
					)
					OR (
						EXCLUDED.file_event_id
							IS NOT NULL
						AND existing.file_event_id =
							EXCLUDED.file_event_id
					)
					THEN 0
					ELSE 1
				END,

			first_observed_at =
				LEAST(
					existing.first_observed_at,
					EXCLUDED.first_observed_at
				),

			last_observed_at =
				GREATEST(
					existing.last_observed_at,
					EXCLUDED.last_observed_at
				),

			updated_at = CURRENT_TIMESTAMP
		RETURNING ` + fingerprintSelectColumns + `;
	`

	row := r.db.QueryRow(
		ctx,
		query,
		fingerprint.ID,
		fingerprint.OrganizationID,
		fingerprint.CanaryFileID,
		fingerprint.AccessLogID,
		fingerprint.FileEventID,
		fingerprint.FingerprintHash,
		fingerprint.FingerprintVersion,
		fingerprint.EventType,
		fingerprint.DeviceIdentifier,
		fingerprint.DeviceName,
		fingerprint.OperatingSystem,
		fingerprint.OperatingSystemUser,
		fingerprint.ProcessName,
		fingerprint.ProcessPath,
		fingerprint.ProcessID,
		fingerprint.ParentProcessName,
		fingerprint.SourceIP,
		interactionPatternJSON,
		fingerprint.BehaviouralScore,
		fingerprint.ConfidenceScore,
		fingerprint.IsSuspicious,
		fingerprint.RansomwareSuspected,
		fingerprint.OccurrenceCount,
		fingerprint.FirstObservedAt,
		fingerprint.LastObservedAt,
		fingerprint.CreatedAt,
		fingerprint.UpdatedAt,
	)

	result, err :=
		scanCanaryInteractionFingerprint(
			row,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"upsert canary interaction fingerprint: %w",
			err,
		)
	}

	return result, nil
}

type fingerprintRowScanner interface {
	Scan(destinations ...any) error
}

func scanCanaryInteractionFingerprint(
	row fingerprintRowScanner,
) (*CanaryInteractionFingerprint, error) {
	var fingerprint CanaryInteractionFingerprint
	var interactionPatternJSON []byte

	if err := row.Scan(
		&fingerprint.ID,
		&fingerprint.FingerprintSequence,
		&fingerprint.OrganizationID,
		&fingerprint.CanaryFileID,
		&fingerprint.AccessLogID,
		&fingerprint.FileEventID,
		&fingerprint.FingerprintHash,
		&fingerprint.FingerprintVersion,
		&fingerprint.EventType,
		&fingerprint.DeviceIdentifier,
		&fingerprint.DeviceName,
		&fingerprint.OperatingSystem,
		&fingerprint.OperatingSystemUser,
		&fingerprint.ProcessName,
		&fingerprint.ProcessPath,
		&fingerprint.ProcessID,
		&fingerprint.ParentProcessName,
		&fingerprint.SourceIP,
		&interactionPatternJSON,
		&fingerprint.BehaviouralScore,
		&fingerprint.ConfidenceScore,
		&fingerprint.IsSuspicious,
		&fingerprint.RansomwareSuspected,
		&fingerprint.OccurrenceCount,
		&fingerprint.FirstObservedAt,
		&fingerprint.LastObservedAt,
		&fingerprint.CreatedAt,
		&fingerprint.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if len(interactionPatternJSON) == 0 {
		fingerprint.InteractionPattern =
			make(map[string]any)
	} else if err := json.Unmarshal(
		interactionPatternJSON,
		&fingerprint.InteractionPattern,
	); err != nil {
		return nil, fmt.Errorf(
			"decode canary interaction pattern: %w",
			err,
		)
	}

	fingerprint.EventType =
		NormalizeConstant(
			fingerprint.EventType,
		)

	fingerprint.FirstObservedAt =
		fingerprint.FirstObservedAt.UTC()

	fingerprint.LastObservedAt =
		fingerprint.LastObservedAt.UTC()

	fingerprint.CreatedAt =
		fingerprint.CreatedAt.UTC()

	fingerprint.UpdatedAt =
		fingerprint.UpdatedAt.UTC()

	return &fingerprint, nil
}
