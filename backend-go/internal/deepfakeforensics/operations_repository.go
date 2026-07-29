package deepfakeforensics

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
)

const mediaMaintenanceExecutionTimeout = 30 * time.Second

func (r *Repository) RecordMediaSecurityEvent(
	ctx context.Context,
	organizationID uuid.UUID,
	assetID uuid.UUID,
	actorUserID *uuid.UUID,
	eventType string,
	reason string,
	metadata map[string]any,
) error {
	if err := r.validateAvailable(); err != nil {
		return err
	}
	return insertMediaSecurityEvent(
		ctx,
		r.databasePool,
		organizationID,
		assetID,
		actorUserID,
		eventType,
		reason,
		metadata,
	)
}

type mediaSecurityEventExecutor interface {
	Exec(
		context.Context,
		string,
		...any,
	) (pgconn.CommandTag, error)
}

func insertMediaSecurityEvent(
	ctx context.Context,
	executor mediaSecurityEventExecutor,
	organizationID uuid.UUID,
	assetID uuid.UUID,
	actorUserID *uuid.UUID,
	eventType string,
	reason string,
	metadata map[string]any,
) error {
	if ctx == nil ||
		executor == nil ||
		organizationID == uuid.Nil ||
		assetID == uuid.Nil {
		return ErrInvalidRepositoryInput
	}
	eventType = NormalizeConstant(eventType)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf(
			"encode media security event metadata: %w",
			err,
		)
	}

	_, err = executor.Exec(
		ctx,
		`
			INSERT INTO media_asset_security_events (
				organization_id,
				media_asset_id,
				event_type,
				actor_user_id,
				reason,
				metadata
			)
			VALUES ($1, $2, $3, $4, $5, $6)
		`,
		organizationID,
		assetID,
		eventType,
		actorUserID,
		reason,
		metadataJSON,
	)
	if err != nil {
		return fmt.Errorf(
			"create media security event: %w",
			err,
		)
	}

	return nil
}

func (r *Repository) ListMediaAssetSecurityEvents(
	ctx context.Context,
	organizationID uuid.UUID,
	assetID uuid.UUID,
	limit int,
	offset int,
) ([]MediaAssetSecurityEvent, int64, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, 0, err
	}
	if ctx == nil ||
		organizationID == uuid.Nil ||
		assetID == uuid.Nil ||
		limit <= 0 ||
		offset < 0 {
		return nil, 0, ErrInvalidRepositoryInput
	}

	if _, err := r.GetMediaAsset(
		ctx,
		organizationID,
		assetID,
	); err != nil {
		return nil, 0, err
	}

	rows, err := r.databasePool.Query(
		ctx,
		`
			SELECT
				id,
				organization_id,
				media_asset_id,
				event_type,
				actor_user_id,
				reason,
				COALESCE(metadata, '{}'::jsonb),
				created_at,
				COUNT(*) OVER()
			FROM media_asset_security_events
			WHERE organization_id = $1
				AND media_asset_id = $2
			ORDER BY created_at DESC, id DESC
			LIMIT $3
			OFFSET $4
		`,
		organizationID,
		assetID,
		limit,
		offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list media security events: %w",
			err,
		)
	}
	defer rows.Close()

	events := make(
		[]MediaAssetSecurityEvent,
		0,
		limit,
	)
	var total int64
	for rows.Next() {
		event := MediaAssetSecurityEvent{}
		var metadataJSON []byte
		if err = rows.Scan(
			&event.ID,
			&event.OrganizationID,
			&event.MediaAssetID,
			&event.EventType,
			&event.ActorUserID,
			&event.Reason,
			&metadataJSON,
			&event.CreatedAt,
			&total,
		); err != nil {
			return nil, 0, fmt.Errorf(
				"scan media security event: %w",
				err,
			)
		}
		event.Metadata = map[string]any{}
		if len(metadataJSON) > 0 {
			if err = json.Unmarshal(
				metadataJSON,
				&event.Metadata,
			); err != nil {
				return nil, 0, fmt.Errorf(
					"decode media security event metadata: %w",
					err,
				)
			}
		}
		events = append(events, event)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate media security events: %w",
			err,
		)
	}

	return events, total, nil
}

// QuarantineMediaAssetForIntegrityFailure is used by the
// worker when disk bytes no longer match the registered
// plaintext hash or authenticated-encryption tag.
func (r *Repository) QuarantineMediaAssetForIntegrityFailure(
	ctx context.Context,
	organizationID uuid.UUID,
	assetID uuid.UUID,
	reason string,
) error {
	if err := r.validateAvailable(); err != nil {
		return err
	}
	if ctx == nil ||
		organizationID == uuid.Nil ||
		assetID == uuid.Nil {
		return ErrInvalidRepositoryInput
	}

	tx, err := r.databasePool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	_, err = tx.Exec(
		ctx,
		`
			UPDATE media_analysis_assets
			SET
				status = $3,
				metadata = COALESCE(
					metadata,
					'{}'::jsonb
					) || jsonb_build_object(
						'integrity_failure',
						true,
						'integrity_failure_reason',
						$4::text,
						'integrity_failure_at',
						CURRENT_TIMESTAMP
				),
				updated_at = CURRENT_TIMESTAMP
			WHERE organization_id = $1
				AND id = $2
				AND deleted_at IS NULL
				AND status NOT IN (
					'ARCHIVED',
					'DELETED'
				)
		`,
		organizationID,
		assetID,
		mediaAssetStatusQuarantined,
		reason,
	)
	if err != nil {
		return fmt.Errorf(
			"quarantine integrity-failed media: %w",
			err,
		)
	}

	_, err = tx.Exec(
		ctx,
		`
			UPDATE ai_analysis_jobs
			SET
				status = $3,
				progress_percentage = 100,
				error_code =
					'MEDIA_STORAGE_INTEGRITY_FAILED',
				error_message = $4,
				cancelled_at = CURRENT_TIMESTAMP,
				completed_at = CURRENT_TIMESTAMP,
				updated_at = CURRENT_TIMESTAMP
			WHERE organization_id = $1
				AND media_asset_id = $2
				AND status IN ($5, $6, $7)
		`,
		organizationID,
		assetID,
		JobStatusCancelled,
		reason,
		JobStatusQueued,
		JobStatusRetrying,
		JobStatusProcessing,
	)
	if err != nil {
		return fmt.Errorf(
			"cancel integrity-failed media jobs: %w",
			err,
		)
	}

	if err = insertMediaSecurityEvent(
		ctx,
		tx,
		organizationID,
		assetID,
		nil,
		"INTEGRITY_FAILED",
		reason,
		map[string]any{
			"automatic": true,
		},
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// RecoverStaleAnalysisJobs safely releases work abandoned
// by a crashed processing node.
func (r *Repository) RecoverStaleAnalysisJobs(
	ctx context.Context,
	cutoff time.Time,
) (int64, error) {
	if err := r.validateAvailable(); err != nil {
		return 0, err
	}
	if ctx == nil ||
		cutoff.IsZero() {
		return 0, ErrInvalidRepositoryInput
	}

	commandTag, err := r.databasePool.Exec(
		ctx,
		`
			UPDATE ai_analysis_jobs
			SET
				retry_count = retry_count + 1,
				status = CASE
					WHEN retry_count + 1 >=
						maximum_retries
						THEN $2::varchar
					ELSE $3::varchar
				END,
				progress_percentage = CASE
					WHEN retry_count + 1 >=
						maximum_retries
						THEN 100
					ELSE 0
				END,
				error_code =
					'STALE_PROCESSING_RECOVERED',
				error_message =
					'Processing lease expired and was recovered',
				processing_node = NULL,
				started_at = NULL,
				queued_at = CASE
					WHEN retry_count + 1 <
						maximum_retries
						THEN CURRENT_TIMESTAMP
					ELSE queued_at
				END,
				completed_at = CASE
					WHEN retry_count + 1 >=
						maximum_retries
						THEN CURRENT_TIMESTAMP
					ELSE NULL
				END,
				updated_at = CURRENT_TIMESTAMP
			WHERE status = $4::varchar
    AND COALESCE(started_at, updated_at) < $1
		`,
		cutoff.UTC(),
		JobStatusFailed,
		JobStatusRetrying,
		JobStatusProcessing,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"recover stale media analysis jobs: %w",
			err,
		)
	}

	return commandTag.RowsAffected(), nil
}

// ArchiveExpiredMediaAssets performs a reversible status
// transition only. Files and database records are retained.
func (r *Repository) ArchiveExpiredMediaAssets(
	ctx context.Context,
	cutoff time.Time,
) (int64, error) {
	if err := r.validateAvailable(); err != nil {
		return 0, err
	}
	if ctx == nil ||
		cutoff.IsZero() {
		return 0, ErrInvalidRepositoryInput
	}

	rows, err := r.databasePool.Query(
		ctx,
		`
			WITH archived AS (
				UPDATE media_analysis_assets AS asset
				SET
					status = $2::varchar,
					metadata = COALESCE(
						metadata,
						'{}'::jsonb
					) || jsonb_build_object(
						'retention_archived_at',
						CURRENT_TIMESTAMP
					),
					updated_at = CURRENT_TIMESTAMP
				WHERE asset.status = $3::varchar
					AND asset.analyzed_at < $1
					AND asset.incident_id IS NULL
					AND asset.evidence_id IS NULL
					AND asset.evidence_file_id IS NULL
					AND asset.deleted_at IS NULL
					AND NOT EXISTS (
						SELECT 1
						FROM ai_analysis_jobs AS job
						WHERE job.organization_id =
								asset.organization_id
							AND job.media_asset_id =
								asset.id
							AND job.status IN (
								$4::varchar,
								$5::varchar,
								$6::varchar
							)
					)
				RETURNING
					asset.organization_id,
					asset.id
			)
			INSERT INTO media_asset_security_events (
				organization_id,
				media_asset_id,
				event_type,
				reason,
				metadata
			)
			SELECT
				organization_id,
				id,
				'RETENTION_ARCHIVED',
				'Retention policy archived media asset',
				jsonb_build_object(
					'automatic',
					true,
					'cutoff',
					$1
				)
			FROM archived
			RETURNING id
		`,
		cutoff.UTC(),
		mediaAssetStatusArchived,
		mediaAssetStatusAvailable,
		JobStatusQueued,
		JobStatusRetrying,
		JobStatusProcessing,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"archive expired media assets: %w",
			err,
		)
	}
	defer rows.Close()

	var archived int64
	for rows.Next() {
		var eventID uuid.UUID
		if err = rows.Scan(&eventID); err != nil {
			return archived, err
		}
		archived++
	}
	if err = rows.Err(); err != nil {
		return archived, err
	}

	return archived, nil
}

func (w *AnalysisWorker) runMaintenance(
	ctx context.Context,
) {
	defer w.wait.Done()

	ticker := time.NewTicker(
		w.maintenancePolicy.Interval,
	)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			w.executeMaintenance(ctx)
		}
	}
}

func (w *AnalysisWorker) executeMaintenance(
	parent context.Context,
) {
	ctx, cancel := context.WithTimeout(
		parent,
		mediaMaintenanceExecutionTimeout,
	)
	defer cancel()

	now := time.Now().UTC()
	recovered, err :=
		w.repository.RecoverStaleAnalysisJobs(
			ctx,
			now.Add(
				-w.maintenancePolicy.
					StaleProcessingTimeout,
			),
		)
	if err != nil {
		w.logger.Warn(
			"Media maintenance could not recover stale jobs",
			zap.Error(err),
		)
	} else if recovered > 0 {
		w.staleJobsRecoveredCount.Add(
			uint64(recovered),
		)
	}

	removed, err :=
		w.fileManager.CleanupTemporaryFiles(
			now.Add(
				-w.maintenancePolicy.
					TemporaryFileTTL,
			),
		)
	if err != nil {
		w.logger.Warn(
			"Media maintenance could not clean temporary files",
			zap.Error(err),
		)
	} else if removed > 0 {
		w.temporaryFilesRemovedCount.Add(
			uint64(removed),
		)
	}

	var archived int64
	retentionEnabled :=
		w.maintenancePolicy.RetentionDays > 0
	if retentionEnabled {
		archived, err =
			w.repository.ArchiveExpiredMediaAssets(
				ctx,
				now.AddDate(
					0,
					0,
					-w.maintenancePolicy.RetentionDays,
				),
			)
		if err != nil {
			w.logger.Warn(
				"Media maintenance could not archive expired assets",
				zap.Error(err),
			)
		} else if archived > 0 {
			w.assetsArchivedCount.Add(
				uint64(archived),
			)
		}
	}

	w.logger.Info(
		"Deepfake forensics media maintenance cycle completed",
		zap.Int64(
			"stale_jobs_recovered",
			recovered,
		),
		zap.Int64(
			"temporary_files_removed",
			int64(removed),
		),
		zap.Int64(
			"assets_archived",
			archived,
		),
		zap.Bool(
			"retention_enabled",
			retentionEnabled,
		),
	)
}
