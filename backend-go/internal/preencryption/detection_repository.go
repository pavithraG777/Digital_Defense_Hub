package preencryption

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrDetectionNotFound = errors.New(
		"pre-encryption detection not found",
	)

	ErrDetectionAlreadyExists = errors.New(
		"pre-encryption detection already exists",
	)

	ErrInvalidDetection = errors.New(
		"invalid pre-encryption detection",
	)
)

const detectionSelectColumns = `
	id,
	detection_sequence,
	detection_code,
	detection_fingerprint,
	organization_id,
	department_id,
	threat_id,
	incident_id,
	device_identifier,
	device_name,
	process_id,
	process_name,
	executable_path,
	parent_process_id,
	parent_process_name,
	command_line,
	window_started_at,
	window_ended_at,
	window_duration_seconds,
	total_event_count,
	unique_file_count,
	unique_extension_count,
	unique_process_count,
	created_event_count,
	modified_event_count,
	renamed_event_count,
	extension_changed_event_count,
	deleted_event_count,
	hash_changed_event_count,
	permission_changed_event_count,
	encrypted_event_count,
	canary_event_count,
	honeytoken_event_count,
	protected_file_event_count,
	high_entropy_write_count,
	total_bytes_changed,
	event_rate_per_minute,
	file_change_rate_per_minute,
	average_entropy_before,
	average_entropy_after,
	average_entropy_delta,
	rule_score,
	ai_score,
	combined_risk_score,
	threat_probability,
	confidence_score,
	risk_level,
	classification,
	detection_stage,
	detection_method,
	risk_factors,
	recommended_actions,
	score_explanation,
	model_name,
	model_version,
	policy_version,
	requires_human_review,
	requires_endpoint_isolation,
	status,
	action_status,
	metadata,
	detected_at,
	reviewed_at,
	mitigated_at,
	created_at,
	updated_at
`

func (r *Repository) CreateDetection(
	ctx context.Context,
	detection Detection,
	contributions []EventContribution,
) (*Detection, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"pre-encryption repository is unavailable",
		)
	}

	if err := normalizeDetectionForCreate(
		&detection,
	); err != nil {
		return nil, err
	}

	normalizedContributions, err :=
		normalizeEventContributions(
			contributions,
		)
	if err != nil {
		return nil, err
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin pre-encryption detection transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	insertQuery := `
		INSERT INTO pre_encryption_detections (
			id,
			detection_code,
			detection_fingerprint,
			organization_id,
			department_id,
			threat_id,
			incident_id,
			device_identifier,
			device_name,
			process_id,
			process_name,
			executable_path,
			parent_process_id,
			parent_process_name,
			command_line,
			window_started_at,
			window_ended_at,
			window_duration_seconds,
			total_event_count,
			unique_file_count,
			unique_extension_count,
			unique_process_count,
			created_event_count,
			modified_event_count,
			renamed_event_count,
			extension_changed_event_count,
			deleted_event_count,
			hash_changed_event_count,
			permission_changed_event_count,
			encrypted_event_count,
			canary_event_count,
			honeytoken_event_count,
			protected_file_event_count,
			high_entropy_write_count,
			total_bytes_changed,
			event_rate_per_minute,
			file_change_rate_per_minute,
			average_entropy_before,
			average_entropy_after,
			average_entropy_delta,
			rule_score,
			ai_score,
			combined_risk_score,
			threat_probability,
			confidence_score,
			risk_level,
			classification,
			detection_stage,
			detection_method,
			risk_factors,
			recommended_actions,
			score_explanation,
			model_name,
			model_version,
			policy_version,
			requires_human_review,
			requires_endpoint_isolation,
			status,
			action_status,
			metadata,
			detected_at,
			reviewed_at,
			mitigated_at,
			created_at,
			updated_at
		)
		VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15,
			$16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25,
			$26, $27, $28, $29, $30,
			$31, $32, $33, $34, $35,
			$36, $37, $38, $39, $40,
			$41, $42, $43, $44, $45,
			$46, $47, $48, $49, $50,
			$51, $52, $53, $54, $55,
			$56, $57, $58, $59, $60,
			$61, $62, $63, $64, $65
		)
		RETURNING ` + detectionSelectColumns + `;
	`

	createdDetection, err :=
		scanDetection(
			tx.QueryRow(
				ctx,
				insertQuery,
				detection.ID,
				detection.DetectionCode,
				detection.DetectionFingerprint,
				detection.OrganizationID,
				detection.DepartmentID,
				detection.ThreatID,
				detection.IncidentID,
				detection.DeviceIdentifier,
				detection.DeviceName,
				detection.ProcessID,
				detection.ProcessName,
				detection.ExecutablePath,
				detection.ParentProcessID,
				detection.ParentProcessName,
				detection.CommandLine,
				detection.WindowStartedAt,
				detection.WindowEndedAt,
				detection.WindowDurationSeconds,
				detection.TotalEventCount,
				detection.UniqueFileCount,
				detection.UniqueExtensionCount,
				detection.UniqueProcessCount,
				detection.CreatedEventCount,
				detection.ModifiedEventCount,
				detection.RenamedEventCount,
				detection.ExtensionChangedEventCount,
				detection.DeletedEventCount,
				detection.HashChangedEventCount,
				detection.PermissionChangedEventCount,
				detection.EncryptedEventCount,
				detection.CanaryEventCount,
				detection.HoneytokenEventCount,
				detection.ProtectedFileEventCount,
				detection.HighEntropyWriteCount,
				detection.TotalBytesChanged,
				detection.EventRatePerMinute,
				detection.FileChangeRatePerMinute,
				detection.AverageEntropyBefore,
				detection.AverageEntropyAfter,
				detection.AverageEntropyDelta,
				detection.RuleScore,
				detection.AIScore,
				detection.CombinedRiskScore,
				detection.ThreatProbability,
				detection.ConfidenceScore,
				detection.RiskLevel,
				detection.Classification,
				detection.DetectionStage,
				detection.DetectionMethod,
				detection.RiskFactors,
				detection.RecommendedActions,
				detection.ScoreExplanation,
				detection.ModelName,
				detection.ModelVersion,
				detection.PolicyVersion,
				detection.RequiresHumanReview,
				detection.RequiresEndpointIsolation,
				detection.Status,
				detection.ActionStatus,
				detection.Metadata,
				detection.DetectedAt,
				detection.ReviewedAt,
				detection.MitigatedAt,
				detection.CreatedAt,
				detection.UpdatedAt,
			),
		)
	if err != nil {
		if isDetectionUniqueViolation(err) {
			return nil, ErrDetectionAlreadyExists
		}

		return nil, fmt.Errorf(
			"insert pre-encryption detection: %w",
			err,
		)
	}

	for _, contribution := range normalizedContributions {
		signalTypesJSON, marshalErr :=
			json.Marshal(
				contribution.SignalTypes,
			)
		if marshalErr != nil {
			return nil, fmt.Errorf(
				"encode detection event signals: %w",
				marshalErr,
			)
		}

		const linkQuery = `
			INSERT INTO pre_encryption_detection_events (
				id,
				organization_id,
				detection_id,
				file_event_id,
				signal_types,
				contribution_score
			)
			SELECT
				$1,
				$2,
				$3,
				$4,
				$5,
				$6
			WHERE EXISTS (
				SELECT 1
				FROM file_events
				WHERE
					id = $4
					AND organization_id = $2
			)
			ON CONFLICT (
				detection_id,
				file_event_id
			)
			DO NOTHING;
		`

		commandTag, linkErr := tx.Exec(
			ctx,
			linkQuery,
			uuid.New(),
			detection.OrganizationID,
			createdDetection.ID,
			contribution.FileEventID,
			signalTypesJSON,
			contribution.ContributionScore,
		)
		if linkErr != nil {
			return nil, fmt.Errorf(
				"link pre-encryption detection event: %w",
				linkErr,
			)
		}

		if commandTag.RowsAffected() == 0 {
			return nil, fmt.Errorf(
				"%w: file event %s is unavailable",
				ErrInvalidDetection,
				contribution.FileEventID,
			)
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit pre-encryption detection transaction: %w",
			err,
		)
	}

	return createdDetection, nil
}

func (r *Repository) GetDetection(
	ctx context.Context,
	organizationID uuid.UUID,
	detectionID uuid.UUID,
) (*Detection, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"pre-encryption repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if detectionID == uuid.Nil {
		return nil, errors.New(
			"detection ID is required",
		)
	}

	query := `
		SELECT ` + detectionSelectColumns + `
		FROM pre_encryption_detections
		WHERE
			id = $1
			AND organization_id = $2;
	`

	detection, err := scanDetection(
		r.db.QueryRow(
			ctx,
			query,
			detectionID,
			organizationID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDetectionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"get pre-encryption detection: %w",
			err,
		)
	}

	return detection, nil
}

func (r *Repository) GetDetectionByFingerprint(
	ctx context.Context,
	organizationID uuid.UUID,
	fingerprint string,
) (*Detection, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"pre-encryption repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	fingerprint = strings.TrimSpace(
		fingerprint,
	)

	if fingerprint == "" {
		return nil, errors.New(
			"detection fingerprint is required",
		)
	}

	query := `
		SELECT ` + detectionSelectColumns + `
		FROM pre_encryption_detections
		WHERE
			organization_id = $1
			AND detection_fingerprint = $2;
	`

	detection, err := scanDetection(
		r.db.QueryRow(
			ctx,
			query,
			organizationID,
			fingerprint,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDetectionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"get detection by fingerprint: %w",
			err,
		)
	}

	return detection, nil
}

type detectionRowScanner interface {
	Scan(destinations ...any) error
}

func scanDetection(
	row detectionRowScanner,
) (*Detection, error) {
	var detection Detection

	err := row.Scan(
		&detection.ID,
		&detection.DetectionSequence,
		&detection.DetectionCode,
		&detection.DetectionFingerprint,
		&detection.OrganizationID,
		&detection.DepartmentID,
		&detection.ThreatID,
		&detection.IncidentID,
		&detection.DeviceIdentifier,
		&detection.DeviceName,
		&detection.ProcessID,
		&detection.ProcessName,
		&detection.ExecutablePath,
		&detection.ParentProcessID,
		&detection.ParentProcessName,
		&detection.CommandLine,
		&detection.WindowStartedAt,
		&detection.WindowEndedAt,
		&detection.WindowDurationSeconds,
		&detection.TotalEventCount,
		&detection.UniqueFileCount,
		&detection.UniqueExtensionCount,
		&detection.UniqueProcessCount,
		&detection.CreatedEventCount,
		&detection.ModifiedEventCount,
		&detection.RenamedEventCount,
		&detection.ExtensionChangedEventCount,
		&detection.DeletedEventCount,
		&detection.HashChangedEventCount,
		&detection.PermissionChangedEventCount,
		&detection.EncryptedEventCount,
		&detection.CanaryEventCount,
		&detection.HoneytokenEventCount,
		&detection.ProtectedFileEventCount,
		&detection.HighEntropyWriteCount,
		&detection.TotalBytesChanged,
		&detection.EventRatePerMinute,
		&detection.FileChangeRatePerMinute,
		&detection.AverageEntropyBefore,
		&detection.AverageEntropyAfter,
		&detection.AverageEntropyDelta,
		&detection.RuleScore,
		&detection.AIScore,
		&detection.CombinedRiskScore,
		&detection.ThreatProbability,
		&detection.ConfidenceScore,
		&detection.RiskLevel,
		&detection.Classification,
		&detection.DetectionStage,
		&detection.DetectionMethod,
		&detection.RiskFactors,
		&detection.RecommendedActions,
		&detection.ScoreExplanation,
		&detection.ModelName,
		&detection.ModelVersion,
		&detection.PolicyVersion,
		&detection.RequiresHumanReview,
		&detection.RequiresEndpointIsolation,
		&detection.Status,
		&detection.ActionStatus,
		&detection.Metadata,
		&detection.DetectedAt,
		&detection.ReviewedAt,
		&detection.MitigatedAt,
		&detection.CreatedAt,
		&detection.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	detection.WindowStartedAt =
		detection.WindowStartedAt.UTC()

	detection.WindowEndedAt =
		detection.WindowEndedAt.UTC()

	detection.DetectedAt =
		detection.DetectedAt.UTC()

	detection.CreatedAt =
		detection.CreatedAt.UTC()

	detection.UpdatedAt =
		detection.UpdatedAt.UTC()

	normalizeOptionalDetectionTime(
		detection.ReviewedAt,
	)

	normalizeOptionalDetectionTime(
		detection.MitigatedAt,
	)

	return &detection, nil
}

func normalizeDetectionForCreate(
	detection *Detection,
) error {
	if detection == nil {
		return ErrInvalidDetection
	}

	if detection.ID == uuid.Nil {
		detection.ID = uuid.New()
	}

	if detection.OrganizationID == uuid.Nil {
		return fmt.Errorf(
			"%w: organization ID is required",
			ErrInvalidDetection,
		)
	}

	detection.DetectionCode =
		strings.TrimSpace(
			detection.DetectionCode,
		)

	detection.DetectionFingerprint =
		strings.TrimSpace(
			detection.DetectionFingerprint,
		)

	if detection.DetectionCode == "" ||
		detection.DetectionFingerprint == "" {
		return fmt.Errorf(
			"%w: detection code and fingerprint are required",
			ErrInvalidDetection,
		)
	}

	if detection.WindowStartedAt.IsZero() ||
		detection.WindowEndedAt.IsZero() {
		return fmt.Errorf(
			"%w: detection window is required",
			ErrInvalidDetection,
		)
	}

	detection.WindowStartedAt =
		detection.WindowStartedAt.UTC()

	detection.WindowEndedAt =
		detection.WindowEndedAt.UTC()

	if detection.WindowEndedAt.Before(
		detection.WindowStartedAt,
	) {
		return fmt.Errorf(
			"%w: invalid detection window",
			ErrInvalidDetection,
		)
	}

	if detection.WindowDurationSeconds < 0 {
		return fmt.Errorf(
			"%w: window duration cannot be negative",
			ErrInvalidDetection,
		)
	}

	if detection.WindowDurationSeconds == 0 {
		detection.WindowDurationSeconds =
			detection.WindowEndedAt.
				Sub(
					detection.WindowStartedAt,
				).
				Seconds()
	}

	if !IsValidScore(detection.RuleScore) ||
		!IsValidScore(
			detection.CombinedRiskScore,
		) {
		return fmt.Errorf(
			"%w: invalid detection score",
			ErrInvalidDetection,
		)
	}

	if err := validateOptionalDetectionScore(
		detection.AIScore,
	); err != nil {
		return err
	}

	if err := validateOptionalDetectionScore(
		detection.ThreatProbability,
	); err != nil {
		return err
	}

	if err := validateOptionalDetectionScore(
		detection.ConfidenceScore,
	); err != nil {
		return err
	}

	detection.RiskLevel =
		NormalizeConstant(
			detection.RiskLevel,
		)

	detection.Classification =
		NormalizeConstant(
			detection.Classification,
		)

	detection.DetectionStage =
		NormalizeConstant(
			detection.DetectionStage,
		)

	detection.DetectionMethod =
		NormalizeConstant(
			detection.DetectionMethod,
		)

	if detection.DetectionMethod == "" {
		detection.DetectionMethod =
			DetectionMethodHybrid
	}

	if !IsSupportedRiskLevel(
		detection.RiskLevel,
	) ||
		!IsSupportedClassification(
			detection.Classification,
		) ||
		!IsSupportedDetectionStage(
			detection.DetectionStage,
		) ||
		!IsSupportedDetectionMethod(
			detection.DetectionMethod,
		) {
		return fmt.Errorf(
			"%w: unsupported detection classification",
			ErrInvalidDetection,
		)
	}

	expectedRiskLevel, valid :=
		RiskLevelFromScore(
			detection.CombinedRiskScore,
		)
	if !valid ||
		expectedRiskLevel != detection.RiskLevel {
		return fmt.Errorf(
			"%w: risk level does not match combined score",
			ErrInvalidDetection,
		)
	}

	detection.Status =
		NormalizeConstant(
			detection.Status,
		)

	if detection.Status == "" {
		detection.Status =
			DetectionStatusOpen
	}

	detection.ActionStatus =
		NormalizeConstant(
			detection.ActionStatus,
		)

	if detection.ActionStatus == "" {
		detection.ActionStatus =
			ActionStatusPending
	}

	if !IsSupportedDetectionStatus(
		detection.Status,
	) ||
		!IsSupportedActionStatus(
			detection.ActionStatus,
		) {
		return fmt.Errorf(
			"%w: unsupported detection status",
			ErrInvalidDetection,
		)
	}

	if err := normalizeDetectionJSON(
		&detection.RiskFactors,
		[]byte(`{}`),
		"object",
	); err != nil {
		return err
	}

	if err := normalizeDetectionJSON(
		&detection.RecommendedActions,
		[]byte(`[]`),
		"array",
	); err != nil {
		return err
	}

	if err := normalizeDetectionJSON(
		&detection.Metadata,
		[]byte(`{}`),
		"object",
	); err != nil {
		return err
	}

	now := time.Now().UTC()

	if detection.DetectedAt.IsZero() {
		detection.DetectedAt = now
	} else {
		detection.DetectedAt =
			detection.DetectedAt.UTC()
	}

	if detection.CreatedAt.IsZero() {
		detection.CreatedAt = now
	} else {
		detection.CreatedAt =
			detection.CreatedAt.UTC()
	}

	if detection.UpdatedAt.IsZero() {
		detection.UpdatedAt = now
	} else {
		detection.UpdatedAt =
			detection.UpdatedAt.UTC()
	}

	return nil
}

func validateOptionalDetectionScore(
	score *float64,
) error {
	if score == nil {
		return nil
	}

	if !IsValidScore(*score) {
		return fmt.Errorf(
			"%w: optional score must be between 0 and 100",
			ErrInvalidDetection,
		)
	}

	return nil
}

func normalizeDetectionJSON(
	value *json.RawMessage,
	defaultValue json.RawMessage,
	expectedType string,
) error {
	if len(*value) == 0 {
		*value = append(
			json.RawMessage(nil),
			defaultValue...,
		)
	}

	if !json.Valid(*value) {
		return fmt.Errorf(
			"%w: invalid JSON payload",
			ErrInvalidDetection,
		)
	}

	var decoded any

	if err := json.Unmarshal(
		*value,
		&decoded,
	); err != nil {
		return fmt.Errorf(
			"%w: decode JSON payload: %v",
			ErrInvalidDetection,
			err,
		)
	}

	switch expectedType {
	case "object":
		if _, valid :=
			decoded.(map[string]any); !valid {
			return fmt.Errorf(
				"%w: JSON payload must be an object",
				ErrInvalidDetection,
			)
		}

	case "array":
		if _, valid :=
			decoded.([]any); !valid {
			return fmt.Errorf(
				"%w: JSON payload must be an array",
				ErrInvalidDetection,
			)
		}
	}

	return nil
}

func normalizeEventContributions(
	contributions []EventContribution,
) ([]EventContribution, error) {
	normalized := make(
		[]EventContribution,
		0,
		len(contributions),
	)

	seenEvents := make(
		map[uuid.UUID]struct{},
	)

	for _, contribution := range contributions {
		if contribution.FileEventID ==
			uuid.Nil {
			return nil, fmt.Errorf(
				"%w: contribution file event ID is required",
				ErrInvalidDetection,
			)
		}

		if _, exists :=
			seenEvents[contribution.FileEventID]; exists {
			return nil, fmt.Errorf(
				"%w: duplicate contribution event",
				ErrInvalidDetection,
			)
		}

		seenEvents[contribution.FileEventID] =
			struct{}{}

		if !IsValidScore(
			contribution.ContributionScore,
		) {
			return nil, fmt.Errorf(
				"%w: invalid contribution score",
				ErrInvalidDetection,
			)
		}

		signals := make(
			[]string,
			0,
			len(contribution.SignalTypes),
		)

		for _, signal := range contribution.SignalTypes {
			signal =
				NormalizeConstant(signal)

			if !IsSupportedSignalType(signal) {
				return nil, fmt.Errorf(
					"%w: unsupported signal %s",
					ErrInvalidDetection,
					signal,
				)
			}

			signals = appendUniqueSignal(
				signals,
				signal,
			)
		}

		if len(signals) == 0 {
			return nil, fmt.Errorf(
				"%w: contribution signals are required",
				ErrInvalidDetection,
			)
		}

		contribution.SignalTypes =
			signals

		normalized = append(
			normalized,
			contribution,
		)
	}

	return normalized, nil
}

func normalizeOptionalDetectionTime(
	value *time.Time,
) {
	if value == nil {
		return
	}

	*value = value.UTC()
}

func isDetectionUniqueViolation(
	err error,
) bool {
	var postgresError *pgconn.PgError

	if !errors.As(
		err,
		&postgresError,
	) {
		return false
	}

	return postgresError.Code == "23505"
}
