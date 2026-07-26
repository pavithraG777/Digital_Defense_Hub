package adaptivedeception

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrCanaryFingerprintSourceNotApplicable = errors.New(
	"file event is not applicable for canary fingerprinting",
)

// GetCanaryInteractionInputFromFileEvent loads one persisted
// CANARY_FILE event and converts it into fingerprint input.
func (r *Repository) GetCanaryInteractionInputFromFileEvent(
	ctx context.Context,
	organizationID uuid.UUID,
	fileEventID uuid.UUID,
) (*CanaryInteractionInput, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"adaptive deception repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if fileEventID == uuid.Nil {
		return nil, errors.New(
			"file event ID is required",
		)
	}

	const query = `
		SELECT
			event.organization_id,
			event.canary_file_id,
			event.event_type,
			event.device_identifier,
			event.device_name,

			NULLIF(
				COALESCE(
					event.metadata ->> 'operating_system',
					event.raw_event ->> 'operating_system'
				),
				''
			) AS operating_system,

			event.system_username,
			event.process_name,
			event.executable_path,
			event.process_id,
			event.parent_process_name,

			CASE
				WHEN event.ip_address IS NULL
					THEN NULL
				ELSE host(event.ip_address)
			END AS source_ip,

			event.is_suspicious,

			(
				event.threat_score >= 80
				OR event.event_type IN (
					'ENCRYPTED',
					'EXTENSION_CHANGED',
					'MULTIPLE_FILE_CHANGES'
				)
			) AS ransomware_suspected,

			event.occurred_at
		FROM file_events event
		WHERE
			event.organization_id = $1
			AND event.id = $2
			AND event.canary_file_id IS NOT NULL
			AND event.source_type = 'CANARY_FILE'
		LIMIT 1;
	`

	input := &CanaryInteractionInput{}

	err := r.db.QueryRow(
		ctx,
		query,
		organizationID,
		fileEventID,
	).Scan(
		&input.OrganizationID,
		&input.CanaryFileID,
		&input.EventType,
		&input.DeviceIdentifier,
		&input.DeviceName,
		&input.OperatingSystem,
		&input.OperatingSystemUser,
		&input.ProcessName,
		&input.ProcessPath,
		&input.ProcessID,
		&input.ParentProcessName,
		&input.SourceIP,
		&input.IsSuspicious,
		&input.RansomwareSuspected,
		&input.OccurredAt,
	)
	if err != nil {
		if errors.Is(
			err,
			pgx.ErrNoRows,
		) {
			return nil,
				ErrCanaryFingerprintSourceNotApplicable
		}

		return nil, fmt.Errorf(
			"load canary fingerprint file event: %w",
			err,
		)
	}

	normalizedEventID := fileEventID
	input.FileEventID = &normalizedEventID

	input.OccurredAt =
		input.OccurredAt.UTC()

	return input, nil
}
