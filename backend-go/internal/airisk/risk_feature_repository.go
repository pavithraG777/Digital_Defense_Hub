package airisk

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const rapidFileChangeRateThreshold = 10.0

func (r *Repository) LoadIncidentRiskFeatures(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentID uuid.UUID,
) (*IncidentRiskFeatures, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"AI risk repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if incidentID == uuid.Nil {
		return nil, errors.New(
			"incident ID is required",
		)
	}

	transaction, err := r.db.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.RepeatableRead,
			AccessMode: pgx.ReadOnly,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"begin incident risk feature transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(ctx)
	}()

	features := &IncidentRiskFeatures{}

	const incidentQuery = `
		SELECT
			incident_category,
			severity,
			priority,
			status,
			detection_source,
			data_exposure_suspected,
			ransomware_suspected,
			device_isolated,
			evidence_preserved,
			COALESCE(
				affected_record_count,
				0
			)::bigint,
			COALESCE(
				estimated_financial_impact,
				0
			)::double precision,
			GREATEST(
				EXTRACT(
					EPOCH FROM (
						(
							CURRENT_TIMESTAMP
							AT TIME ZONE 'UTC'
						) - detected_at
					)
				) / 60.0,
				0
			)::double precision,
			GREATEST(
				EXTRACT(
					EPOCH FROM (
						reported_at -
						detected_at
					)
				) / 60.0,
				0
			)::double precision,
			CASE
				WHEN investigation_started_at IS NULL
					THEN 0
				ELSE GREATEST(
					EXTRACT(
						EPOCH FROM (
							(
								CURRENT_TIMESTAMP
								AT TIME ZONE 'UTC'
							) -
							investigation_started_at
						)
					) / 60.0,
					0
				)
			END::double precision
		FROM incidents
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL;
	`

	err = transaction.QueryRow(
		ctx,
		incidentQuery,
		incidentID,
		organizationID,
	).Scan(
		&features.IncidentCategory,
		&features.IncidentSeverity,
		&features.IncidentPriority,
		&features.IncidentStatus,
		&features.DetectionSource,
		&features.DataExposureSuspected,
		&features.RansomwareSuspected,
		&features.DeviceIsolated,
		&features.EvidencePreserved,
		&features.AffectedRecordCount,
		&features.EstimatedFinancialImpact,
		&features.IncidentAgeMinutes,
		&features.ReportingDelayMinutes,
		&features.InvestigationAgeMinutes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRiskSubjectNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"load incident risk features: %w",
			err,
		)
	}

	const threatQuery = `
		WITH linked_threats AS (
			SELECT DISTINCT
				t.id,
				t.severity,
				t.classification,
				t.status,
				t.threat_score,
				t.confidence_score,
				t.occurrence_count,
				t.affected_file_count,
				t.affected_device_count
			FROM incident_threats it
			INNER JOIN threats t
				ON t.id = it.threat_id
			WHERE
				it.incident_id = $1
				AND t.organization_id = $2
				AND t.deleted_at IS NULL
		)
		SELECT
			COUNT(*)::bigint,
			COUNT(*) FILTER (
				WHERE severity = 'CRITICAL'
			)::bigint,
			COUNT(*) FILTER (
				WHERE severity = 'HIGH'
			)::bigint,
			COUNT(*) FILTER (
				WHERE classification = 'MALICIOUS'
			)::bigint,
			COUNT(*) FILTER (
				WHERE status IN (
					'CONFIRMED',
					'MITIGATED',
					'RESOLVED'
				)
			)::bigint,
			COUNT(*) FILTER (
				WHERE status NOT IN (
					'MITIGATED',
					'RESOLVED',
					'ARCHIVED',
					'FALSE_POSITIVE'
				)
			)::bigint,
			COALESCE(
				MAX(threat_score),
				0
			)::double precision,
			COALESCE(
				AVG(threat_score),
				0
			)::double precision,
			COALESCE(
				MAX(confidence_score),
				0
			)::double precision,
			COALESCE(
				SUM(occurrence_count),
				0
			)::bigint,
			COALESCE(
				SUM(affected_file_count),
				0
			)::bigint,
			COALESCE(
				SUM(affected_device_count),
				0
			)::bigint
		FROM linked_threats;
	`

	err = transaction.QueryRow(
		ctx,
		threatQuery,
		incidentID,
		organizationID,
	).Scan(
		&features.LinkedThreatCount,
		&features.CriticalThreatCount,
		&features.HighThreatCount,
		&features.MaliciousThreatCount,
		&features.ConfirmedThreatCount,
		&features.UnresolvedThreatCount,
		&features.MaximumThreatScore,
		&features.AverageThreatScore,
		&features.MaximumConfidenceScore,
		&features.TotalThreatOccurrences,
		&features.TotalAffectedFileCount,
		&features.TotalAffectedDeviceCount,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"load incident threat risk features: %w",
			err,
		)
	}

	const fileEventQuery = `
		WITH linked_threats AS (
			SELECT DISTINCT
				t.id,
				t.primary_event_id
			FROM incident_threats it
			INNER JOIN threats t
				ON t.id = it.threat_id
			WHERE
				it.incident_id = $1
				AND t.organization_id = $2
				AND t.deleted_at IS NULL
		),
		linked_event_ids AS (
			SELECT
				tfe.file_event_id
			FROM linked_threats lt
			INNER JOIN threat_file_events tfe
				ON tfe.threat_id = lt.id

			UNION

			SELECT
				lt.primary_event_id
			FROM linked_threats lt
			WHERE lt.primary_event_id IS NOT NULL
		),
		linked_events AS (
			SELECT DISTINCT
				fe.id,
				fe.source_type,
				fe.event_type,
				fe.is_suspicious,
				fe.device_identifier,
				fe.occurred_at
			FROM linked_event_ids lei
			INNER JOIN file_events fe
				ON fe.id = lei.file_event_id
			WHERE fe.organization_id = $2
		)
		SELECT
			COUNT(*)::bigint,
			COUNT(*) FILTER (
				WHERE is_suspicious = TRUE
			)::bigint,
			COUNT(*) FILTER (
				WHERE event_type = 'ENCRYPTED'
			)::bigint,
			COUNT(*) FILTER (
				WHERE event_type =
					'MULTIPLE_FILE_CHANGES'
			)::bigint,
			COUNT(*) FILTER (
				WHERE event_type = 'HASH_CHANGED'
			)::bigint,
			COUNT(*) FILTER (
				WHERE event_type = 'DELETED'
			)::bigint,
			COUNT(*) FILTER (
				WHERE event_type =
					'PERMISSION_CHANGED'
			)::bigint,
			COUNT(*) FILTER (
				WHERE source_type = 'CANARY_FILE'
			)::bigint,
			COUNT(*) FILTER (
				WHERE source_type = 'HONEYTOKEN'
			)::bigint,
			COUNT(*) FILTER (
				WHERE source_type = 'PROTECTED_FILE'
			)::bigint,
			COUNT(
				DISTINCT NULLIF(
					BTRIM(device_identifier),
					''
				)
			)::bigint,
			COALESCE(
				EXTRACT(
					EPOCH FROM (
						MAX(occurred_at) -
						MIN(occurred_at)
					)
				),
				0
			)::double precision
		FROM linked_events;
	`

	err = transaction.QueryRow(
		ctx,
		fileEventQuery,
		incidentID,
		organizationID,
	).Scan(
		&features.FileEventCount,
		&features.SuspiciousFileEventCount,
		&features.EncryptedEventCount,
		&features.MultipleFileChangeEventCount,
		&features.HashChangeEventCount,
		&features.DeletedFileEventCount,
		&features.PermissionChangeEventCount,
		&features.CanaryFileEventCount,
		&features.HoneytokenEventCount,
		&features.ProtectedFileEventCount,
		&features.UniqueDeviceCount,
		&features.EventWindowSeconds,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"load incident file-event risk features: %w",
			err,
		)
	}

	const evidenceQuery = `
		SELECT
			COUNT(*)::bigint,
			COUNT(*) FILTER (
				WHERE integrity_status = 'VERIFIED'
			)::bigint,
			COUNT(*) FILTER (
				WHERE integrity_status = 'TAMPERED'
			)::bigint
		FROM incident_evidence
		WHERE incident_id = $1;
	`

	err = transaction.QueryRow(
		ctx,
		evidenceQuery,
		incidentID,
	).Scan(
		&features.EvidenceCount,
		&features.VerifiedEvidenceCount,
		&features.TamperedEvidenceCount,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"load incident evidence risk features: %w",
			err,
		)
	}

	features.EventRatePerMinute =
		calculateEventRatePerMinute(
			features.FileEventCount,
			features.EventWindowSeconds,
		)

	features.HasCanaryTrigger =
		features.CanaryFileEventCount > 0

	features.HasHoneytokenAccess =
		features.HoneytokenEventCount > 0

	features.HasEncryptionIndicators =
		features.EncryptedEventCount > 0 ||
			features.RansomwareSuspected

	features.HasRapidFileChanges =
		features.MultipleFileChangeEventCount > 0 ||
			features.EventRatePerMinute >=
				rapidFileChangeRateThreshold

	features.HasHashChanges =
		features.HashChangeEventCount > 0

	features.HasFileDeletion =
		features.DeletedFileEventCount > 0

	features.HasPermissionChanges =
		features.PermissionChangeEventCount > 0

	if err = transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit incident risk feature transaction: %w",
			err,
		)
	}

	return features, nil
}

func calculateEventRatePerMinute(
	eventCount int64,
	eventWindowSeconds float64,
) float64 {
	if eventCount <= 0 {
		return 0
	}

	eventWindowMinutes :=
		eventWindowSeconds / 60.0

	if eventWindowMinutes < 1 {
		eventWindowMinutes = 1
	}

	return float64(eventCount) /
		eventWindowMinutes
}
