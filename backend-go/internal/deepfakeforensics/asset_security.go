package deepfakeforensics

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maximumMediaQuarantineReasonLength = 1000

// QuarantineMediaAsset isolates an organization asset and
// cancels any queued or running work that references it.
func (s *AssetService) QuarantineMediaAsset(
	ctx context.Context,
	organizationID uuid.UUID,
	assetID uuid.UUID,
	actorUserID uuid.UUID,
	request MediaAssetQuarantineRequest,
) (*MediaAnalysisAsset, error) {
	reason, err := validateQuarantineReason(
		request.Reason,
	)
	if err != nil {
		return nil, err
	}
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		assetID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidMediaUpload
	}

	return s.repository.SetMediaAssetQuarantine(
		ctx,
		organizationID,
		assetID,
		actorUserID,
		reason,
		true,
	)
}

// ReleaseMediaAsset verifies the stored bytes before a
// quarantined asset can return to the analysis queue.
func (s *AssetService) ReleaseMediaAsset(
	ctx context.Context,
	organizationID uuid.UUID,
	assetID uuid.UUID,
	actorUserID uuid.UUID,
	request MediaAssetQuarantineRequest,
) (*MediaAnalysisAsset, error) {
	reason, err := validateQuarantineReason(
		request.Reason,
	)
	if err != nil {
		return nil, err
	}
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		assetID == uuid.Nil ||
		actorUserID == uuid.Nil {
		return nil, ErrInvalidMediaUpload
	}

	asset, err := s.repository.GetMediaAsset(
		ctx,
		organizationID,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	if NormalizeConstant(asset.Status) !=
		mediaAssetStatusQuarantined {
		return nil, ErrMediaAssetConflict
	}

	if err = s.fileManager.ValidateStoredAsset(
		ctx,
		*asset,
	); err != nil {
		_ = s.repository.RecordMediaSecurityEvent(
			context.Background(),
			organizationID,
			assetID,
			&actorUserID,
			"INTEGRITY_FAILED",
			"Quarantine release validation failed",
			map[string]any{
				"error": safeAnalysisErrorMessage(
					err,
				),
			},
		)
		return nil, err
	}

	return s.repository.SetMediaAssetQuarantine(
		ctx,
		organizationID,
		assetID,
		actorUserID,
		reason,
		false,
	)
}

// ListMediaAssetSecurityEvents returns the immutable audit
// trail for one organization-owned media asset.
func (s *AssetService) ListMediaAssetSecurityEvents(
	ctx context.Context,
	organizationID uuid.UUID,
	assetID uuid.UUID,
	page int,
	pageSize int,
) (*MediaAssetSecurityEventPage, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		assetID == uuid.Nil {
		return nil, ErrInvalidMediaUpload
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	items, total, err :=
		s.repository.ListMediaAssetSecurityEvents(
			ctx,
			organizationID,
			assetID,
			pageSize,
			(page-1)*pageSize,
		)
	if err != nil {
		return nil, err
	}

	totalPages := 0
	if total > 0 {
		totalPages = int(
			(total + int64(pageSize) - 1) /
				int64(pageSize),
		)
	}

	return &MediaAssetSecurityEventPage{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func (r *Repository) SetMediaAssetQuarantine(
	ctx context.Context,
	organizationID uuid.UUID,
	assetID uuid.UUID,
	actorUserID uuid.UUID,
	reason string,
	quarantined bool,
) (*MediaAnalysisAsset, error) {
	if err := r.validateAvailable(); err != nil {
		return nil, err
	}

	targetStatus := mediaAssetStatusAvailable
	eventType := "RELEASED"
	expectedStatus := mediaAssetStatusQuarantined
	if quarantined {
		targetStatus = mediaAssetStatusQuarantined
		eventType = "QUARANTINED"
		expectedStatus = ""
	}

	tx, err := r.databasePool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"begin media quarantine transaction: %w",
			err,
		)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	query := `
		UPDATE media_analysis_assets
		SET
			status = $4::varchar,
			metadata = COALESCE(
				metadata,
				'{}'::jsonb
			) || jsonb_build_object(
				'quarantine_status',
				$4::varchar,
				'quarantine_reason',
				$5::text,
				'quarantine_actor_user_id',
				$3::text,
				'quarantine_updated_at',
				CURRENT_TIMESTAMP
			),
			updated_at = CURRENT_TIMESTAMP
		WHERE organization_id = $1
			AND id = $2
			AND deleted_at IS NULL
			AND (
				$6::varchar = ''
				OR status = $6::varchar
			)
			AND status NOT IN (
				'ARCHIVED',
				'DELETED'
			)
	`
	commandTag, err := tx.Exec(
		ctx,
		query,
		organizationID,
		assetID,
		actorUserID,
		targetStatus,
		reason,
		expectedStatus,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"update media quarantine status: %w",
			err,
		)
	}
	if commandTag.RowsAffected() != 1 {
		return nil, ErrMediaAssetConflict
	}

	if quarantined {
		_, err = tx.Exec(
			ctx,
			`
				UPDATE ai_analysis_jobs
				SET
					status = $3,
					progress_percentage = 100,
					error_code = 'MEDIA_ASSET_QUARANTINED',
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
			return nil, fmt.Errorf(
				"cancel quarantined media jobs: %w",
				err,
			)
		}
	}

	if err = insertMediaSecurityEvent(
		ctx,
		tx,
		organizationID,
		assetID,
		&actorUserID,
		eventType,
		reason,
		map[string]any{
			"status": targetStatus,
		},
	); err != nil {
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit media quarantine transaction: %w",
			err,
		)
	}

	return r.GetMediaAsset(
		ctx,
		organizationID,
		assetID,
	)
}

func validateQuarantineReason(
	value string,
) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" ||
		len(value) >
			maximumMediaQuarantineReasonLength {
		return "", fmt.Errorf(
			"%w: quarantine reason is required and must not exceed %d characters",
			ErrInvalidMediaUpload,
			maximumMediaQuarantineReasonLength,
		)
	}
	return value, nil
}
