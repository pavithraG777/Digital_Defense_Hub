package notification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrNotificationStateConflict = errors.New(
	"notification state conflict",
)

func (r *Repository) RefreshNotificationDeliveryStatus(
	ctx context.Context,
	organizationID uuid.UUID,
	notificationID uuid.UUID,
	updatedAt time.Time,
) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New(
			"notification repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return "", errors.New(
			"organization ID is required",
		)
	}

	if notificationID == uuid.Nil {
		return "", errors.New(
			"notification ID is required",
		)
	}

	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	} else {
		updatedAt = updatedAt.UTC()
	}

	const query = `
		WITH delivery_statistics AS (
			SELECT
				COUNT(*) AS total_count,
				COUNT(*) FILTER (
					WHERE delivery_status IN (
						'QUEUED',
						'RETRY_SCHEDULED',
						'PROCESSING'
					)
				) AS pending_count,
				COUNT(*) FILTER (
					WHERE delivery_status IN (
						'SENT',
						'DELIVERED',
						'SKIPPED'
					)
				) AS successful_count,
				COUNT(*) FILTER (
					WHERE delivery_status = 'FAILED'
				) AS failed_count,
				COUNT(*) FILTER (
					WHERE delivery_status = 'CANCELLED'
				) AS cancelled_count
			FROM notification_deliveries
			WHERE
				notification_id = $1
				AND organization_id = $2
		)
		UPDATE notifications n
		SET
			status = CASE
				WHEN n.status IN (
					'CANCELLED',
					'EXPIRED'
				)
					THEN n.status

				WHEN ds.total_count = 0
					THEN 'CREATED'

				WHEN ds.successful_count = ds.total_count
					THEN 'SENT'

				WHEN (
					ds.failed_count +
					ds.cancelled_count
				) = ds.total_count
					THEN 'FAILED'

				WHEN ds.successful_count > 0
					THEN 'PARTIALLY_SENT'

				WHEN ds.pending_count > 0
					THEN 'QUEUED'

				WHEN ds.failed_count > 0
					THEN 'FAILED'

				ELSE 'QUEUED'
			END,
			updated_at = $3
		FROM delivery_statistics ds
		WHERE
			n.id = $1
			AND n.organization_id = $2
			AND n.deleted_at IS NULL
		RETURNING n.status;
	`

	var status string

	err := r.db.QueryRow(
		ctx,
		query,
		notificationID,
		organizationID,
		updatedAt,
	).Scan(&status)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotificationNotFound
	}

	if err != nil {
		return "", fmt.Errorf(
			"refresh notification delivery status: %w",
			err,
		)
	}

	return status, nil
}

func (r *Repository) CancelNotification(
	ctx context.Context,
	organizationID uuid.UUID,
	notificationID uuid.UUID,
	cancelledAt time.Time,
) (*Notification, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"notification repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if notificationID == uuid.Nil {
		return nil, errors.New(
			"notification ID is required",
		)
	}

	if cancelledAt.IsZero() {
		cancelledAt = time.Now().UTC()
	} else {
		cancelledAt = cancelledAt.UTC()
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin cancel notification transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const stateQuery = `
		SELECT status
		FROM notifications
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL
		FOR UPDATE;
	`

	var currentStatus string

	err = tx.QueryRow(
		ctx,
		stateQuery,
		notificationID,
		organizationID,
	).Scan(&currentStatus)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotificationNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"load notification cancellation state: %w",
			err,
		)
	}

	switch currentStatus {
	case "SENT", "EXPIRED":
		return nil, fmt.Errorf(
			"%w: notification with status %s cannot be cancelled",
			ErrNotificationStateConflict,
			currentStatus,
		)
	}

	const cancelDeliveriesQuery = `
		UPDATE notification_deliveries
		SET
			delivery_status = 'CANCELLED',
			next_retry_at = NULL,
			processing_started_at = NULL,
			updated_at = $3
		WHERE
			notification_id = $1
			AND organization_id = $2
			AND delivery_status IN (
				'QUEUED',
				'RETRY_SCHEDULED',
				'PROCESSING'
			);
	`

	if _, err = tx.Exec(
		ctx,
		cancelDeliveriesQuery,
		notificationID,
		organizationID,
		cancelledAt,
	); err != nil {
		return nil, fmt.Errorf(
			"cancel notification deliveries: %w",
			err,
		)
	}

	updateNotificationQuery := `
		UPDATE notifications n
		SET
			status = 'CANCELLED',
			updated_at = $3
		WHERE
			n.id = $1
			AND n.organization_id = $2
			AND n.deleted_at IS NULL
		RETURNING ` + notificationQuerySelectColumns + `;
	`

	notificationRecord, err := scanNotificationQuery(
		tx.QueryRow(
			ctx,
			updateNotificationQuery,
			notificationID,
			organizationID,
			cancelledAt,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"update cancelled notification: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit notification cancellation: %w",
			err,
		)
	}

	return notificationRecord, nil
}

func (r *Repository) RequeueStaleProcessingDeliveries(
	ctx context.Context,
	staleBefore time.Time,
	retryAt time.Time,
) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New(
			"notification repository is unavailable",
		)
	}

	if staleBefore.IsZero() {
		return 0, errors.New(
			"stale processing cutoff time is required",
		)
	}

	staleBefore = staleBefore.UTC()

	if retryAt.IsZero() {
		retryAt = time.Now().UTC()
	} else {
		retryAt = retryAt.UTC()
	}

	const query = `
		UPDATE notification_deliveries d
		SET
			delivery_status = CASE
				WHEN n.status IN (
					'CANCELLED',
					'EXPIRED'
				)
					THEN 'CANCELLED'

				WHEN d.attempt_count < d.maximum_attempts
					THEN 'RETRY_SCHEDULED'

				ELSE 'FAILED'
			END,

			next_retry_at = CASE
				WHEN n.status IN (
					'CANCELLED',
					'EXPIRED'
				)
					THEN NULL::timestamp without time zone

				WHEN d.attempt_count < d.maximum_attempts
					THEN $2::timestamp without time zone

				ELSE NULL::timestamp without time zone
			END,

			processing_started_at = NULL,

			last_error = CASE
				WHEN n.status IN (
					'CANCELLED',
					'EXPIRED'
				)
					THEN COALESCE(
						d.last_error,
						'parent notification is inactive'
					)

				ELSE COALESCE(
					d.last_error,
					'delivery processing timeout'
				)
			END,

			failed_at = CASE
				WHEN n.status NOT IN (
					'CANCELLED',
					'EXPIRED'
				)
				AND d.attempt_count >= d.maximum_attempts
					THEN $2::timestamp without time zone

				ELSE d.failed_at
			END,

			updated_at =
				$2::timestamp without time zone

		FROM notifications n
		WHERE
			n.id = d.notification_id
			AND n.organization_id =
				d.organization_id
			AND d.delivery_status = 'PROCESSING'
			AND d.processing_started_at IS NOT NULL
			AND d.processing_started_at <=
				$1::timestamp without time zone;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		staleBefore,
		retryAt,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"requeue stale notification deliveries: %w",
			err,
		)
	}

	return commandTag.RowsAffected(), nil
}
func (r *Repository) ExpireNotifications(
	ctx context.Context,
	expiredAt time.Time,
) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New(
			"notification repository is unavailable",
		)
	}

	if expiredAt.IsZero() {
		expiredAt = time.Now().UTC()
	} else {
		expiredAt = expiredAt.UTC()
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf(
			"begin expire notifications transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const expireNotificationsQuery = `
		UPDATE notifications
		SET
			status = 'EXPIRED',
			updated_at = $1
		WHERE
			expires_at IS NOT NULL
			AND expires_at <= $1
			AND status IN (
				'CREATED',
				'QUEUED',
				'PARTIALLY_SENT'
			)
			AND deleted_at IS NULL;
	`

	commandTag, err := tx.Exec(
		ctx,
		expireNotificationsQuery,
		expiredAt,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"expire notifications: %w",
			err,
		)
	}

	const cancelExpiredDeliveriesQuery = `
		UPDATE notification_deliveries d
		SET
			delivery_status = 'CANCELLED',
			next_retry_at = NULL,
			processing_started_at = NULL,
			last_error = COALESCE(
				d.last_error,
				'notification expired before delivery'
			),
			updated_at = $1
		FROM notifications n
		WHERE
			n.id = d.notification_id
			AND n.organization_id = d.organization_id
			AND n.status = 'EXPIRED'
			AND n.expires_at IS NOT NULL
			AND n.expires_at <= $1
			AND d.delivery_status IN (
				'QUEUED',
				'RETRY_SCHEDULED',
				'PROCESSING'
			);
	`

	if _, err = tx.Exec(
		ctx,
		cancelExpiredDeliveriesQuery,
		expiredAt,
	); err != nil {
		return 0, fmt.Errorf(
			"cancel expired notification deliveries: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf(
			"commit notification expiration: %w",
			err,
		)
	}

	return commandTag.RowsAffected(), nil
}
