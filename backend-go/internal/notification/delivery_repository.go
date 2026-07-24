package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrNotificationDeliveryNotFound = errors.New(
		"notification delivery not found",
	)
	ErrNotificationDeliveryStateConflict = errors.New(
		"notification delivery state conflict",
	)
	ErrInvalidNotificationProviderResponse = errors.New(
		"invalid notification provider response",
	)
)

const notificationDeliveryWorkflowColumns = `
	d.id,
	d.notification_id,
	d.recipient_id,
	d.organization_id,
	d.channel,
	d.delivery_status,
	d.attempt_count,
	d.maximum_attempts,
	d.provider_name,
	d.provider_message_id,
	d.last_error,
	d.provider_response,
	d.scheduled_at,
	d.next_retry_at,
	d.processing_started_at,
	d.sent_at,
	d.delivered_at,
	d.failed_at,
	d.created_at,
	d.updated_at
`

type notificationDeliveryWorkflowScanner interface {
	Scan(dest ...any) error
}

type MarkNotificationDeliverySentInput struct {
	OrganizationID    uuid.UUID
	DeliveryID        uuid.UUID
	ProviderName      *string
	ProviderMessageID *string
	ProviderResponse  json.RawMessage
	SentAt            time.Time
}

type MarkNotificationDeliveryDeliveredInput struct {
	OrganizationID   uuid.UUID
	DeliveryID       uuid.UUID
	ProviderResponse json.RawMessage
	DeliveredAt      time.Time
}

type MarkNotificationDeliveryFailedInput struct {
	OrganizationID   uuid.UUID
	DeliveryID       uuid.UUID
	LastError        string
	ProviderResponse json.RawMessage
	RetryAt          *time.Time
	FailedAt         time.Time
}

func (r *Repository) ClaimPendingDeliveries(
	ctx context.Context,
	limit int,
	claimedAt time.Time,
) ([]Delivery, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"notification repository is unavailable",
		)
	}

	if limit <= 0 {
		limit = 20
	}

	if limit > 100 {
		limit = 100
	}

	if claimedAt.IsZero() {
		claimedAt = time.Now().UTC()
	} else {
		claimedAt = claimedAt.UTC()
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin claim notification deliveries: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	query := `
		WITH delivery_candidates AS (
			SELECT d.id
			FROM notification_deliveries d
			INNER JOIN notifications n
				ON n.id = d.notification_id
				AND n.organization_id = d.organization_id
			WHERE
				d.delivery_status IN (
					'QUEUED',
					'RETRY_SCHEDULED'
				)
				AND d.attempt_count < d.maximum_attempts
				AND d.scheduled_at <= $1
				AND (
					d.next_retry_at IS NULL
					OR d.next_retry_at <= $1
				)
				AND n.status NOT IN (
					'CANCELLED',
					'EXPIRED',
					'FAILED'
				)
				AND (
					n.expires_at IS NULL
					OR n.expires_at > $1
				)
				AND n.deleted_at IS NULL
			ORDER BY
				n.priority_level DESC,
				d.scheduled_at ASC,
				d.created_at ASC
			FOR UPDATE OF d SKIP LOCKED
			LIMIT $2
		)
		UPDATE notification_deliveries d
		SET
			delivery_status = 'PROCESSING',
			attempt_count = d.attempt_count + 1,
			processing_started_at = $1,
			next_retry_at = NULL,
			updated_at = $1
		FROM delivery_candidates dc
		WHERE d.id = dc.id
		RETURNING ` + notificationDeliveryWorkflowColumns + `;
	`

	rows, err := tx.Query(
		ctx,
		query,
		claimedAt,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"claim pending notification deliveries: %w",
			err,
		)
	}
	defer rows.Close()

	deliveries := make(
		[]Delivery,
		0,
		limit,
	)

	for rows.Next() {
		delivery, scanErr :=
			scanNotificationDeliveryWorkflow(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan claimed notification delivery: %w",
				scanErr,
			)
		}

		deliveries = append(
			deliveries,
			*delivery,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate claimed notification deliveries: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit claimed notification deliveries: %w",
			err,
		)
	}

	return deliveries, nil
}

func (r *Repository) MarkDeliverySent(
	ctx context.Context,
	input MarkNotificationDeliverySentInput,
) (*Delivery, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"notification repository is unavailable",
		)
	}

	if input.OrganizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if input.DeliveryID == uuid.Nil {
		return nil, errors.New(
			"delivery ID is required",
		)
	}

	if input.SentAt.IsZero() {
		input.SentAt = time.Now().UTC()
	} else {
		input.SentAt = input.SentAt.UTC()
	}

	providerName := normalizeNotificationDeliveryString(
		input.ProviderName,
	)

	providerMessageID :=
		normalizeNotificationDeliveryString(
			input.ProviderMessageID,
		)

	providerResponse, err :=
		normalizeNotificationProviderResponse(
			input.ProviderResponse,
		)
	if err != nil {
		return nil, err
	}

	query := `
		UPDATE notification_deliveries d
		SET
			delivery_status = 'SENT',
			provider_name = COALESCE(
				$3,
				d.provider_name
			),
			provider_message_id = COALESCE(
				$4,
				d.provider_message_id
			),
			provider_response = $5,
			last_error = NULL,
			next_retry_at = NULL,
			processing_started_at = NULL,
			sent_at = COALESCE(
				d.sent_at,
				$6
			),
			failed_at = NULL,
			updated_at = $6
		WHERE
			d.id = $1
			AND d.organization_id = $2
			AND d.delivery_status = 'PROCESSING'
		RETURNING ` + notificationDeliveryWorkflowColumns + `;
	`

	delivery, err := scanNotificationDeliveryWorkflow(
		r.db.QueryRow(
			ctx,
			query,
			input.DeliveryID,
			input.OrganizationID,
			providerName,
			providerMessageID,
			providerResponse,
			input.SentAt,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, r.resolveNotificationDeliveryUpdateError(
			ctx,
			input.OrganizationID,
			input.DeliveryID,
		)
	}

	if err != nil {
		return nil, fmt.Errorf(
			"mark notification delivery sent: %w",
			err,
		)
	}

	return delivery, nil
}

func (r *Repository) MarkDeliveryDelivered(
	ctx context.Context,
	input MarkNotificationDeliveryDeliveredInput,
) (*Delivery, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"notification repository is unavailable",
		)
	}

	if input.OrganizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if input.DeliveryID == uuid.Nil {
		return nil, errors.New(
			"delivery ID is required",
		)
	}

	if input.DeliveredAt.IsZero() {
		input.DeliveredAt = time.Now().UTC()
	} else {
		input.DeliveredAt =
			input.DeliveredAt.UTC()
	}

	providerResponse, err :=
		normalizeNotificationProviderResponse(
			input.ProviderResponse,
		)
	if err != nil {
		return nil, err
	}

	query := `
		UPDATE notification_deliveries d
		SET
			delivery_status = 'DELIVERED',
			provider_response = CASE
				WHEN $3::jsonb = '{}'::jsonb
					THEN d.provider_response
				ELSE $3::jsonb
			END,
			last_error = NULL,
			next_retry_at = NULL,
			processing_started_at = NULL,
			sent_at = COALESCE(
				d.sent_at,
				$4
			),
			delivered_at = COALESCE(
				d.delivered_at,
				$4
			),
			failed_at = NULL,
			updated_at = $4
		WHERE
			d.id = $1
			AND d.organization_id = $2
			AND d.delivery_status IN (
				'PROCESSING',
				'SENT'
			)
		RETURNING ` + notificationDeliveryWorkflowColumns + `;
	`

	delivery, err := scanNotificationDeliveryWorkflow(
		r.db.QueryRow(
			ctx,
			query,
			input.DeliveryID,
			input.OrganizationID,
			providerResponse,
			input.DeliveredAt,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, r.resolveNotificationDeliveryUpdateError(
			ctx,
			input.OrganizationID,
			input.DeliveryID,
		)
	}

	if err != nil {
		return nil, fmt.Errorf(
			"mark notification delivery delivered: %w",
			err,
		)
	}

	return delivery, nil
}

func (r *Repository) MarkDeliveryFailed(
	ctx context.Context,
	input MarkNotificationDeliveryFailedInput,
) (*Delivery, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"notification repository is unavailable",
		)
	}

	if input.OrganizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if input.DeliveryID == uuid.Nil {
		return nil, errors.New(
			"delivery ID is required",
		)
	}

	input.LastError = strings.TrimSpace(
		input.LastError,
	)
	if input.LastError == "" {
		return nil, errors.New(
			"delivery failure reason is required",
		)
	}

	if input.FailedAt.IsZero() {
		input.FailedAt = time.Now().UTC()
	} else {
		input.FailedAt = input.FailedAt.UTC()
	}

	if input.RetryAt != nil {
		normalizedRetryAt :=
			input.RetryAt.UTC()

		if !normalizedRetryAt.After(
			input.FailedAt,
		) {
			return nil, errors.New(
				"delivery retry time must be after failure time",
			)
		}

		input.RetryAt = &normalizedRetryAt
	}

	providerResponse, err :=
		normalizeNotificationProviderResponse(
			input.ProviderResponse,
		)
	if err != nil {
		return nil, err
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin notification delivery failure transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const stateQuery = `
		SELECT
			delivery_status,
			attempt_count,
			maximum_attempts
		FROM notification_deliveries
		WHERE
			id = $1
			AND organization_id = $2
		FOR UPDATE;
	`

	var (
		currentStatus   string
		attemptCount    int
		maximumAttempts int
	)

	err = tx.QueryRow(
		ctx,
		stateQuery,
		input.DeliveryID,
		input.OrganizationID,
	).Scan(
		&currentStatus,
		&attemptCount,
		&maximumAttempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotificationDeliveryNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"load notification delivery state: %w",
			err,
		)
	}

	if currentStatus != "PROCESSING" {
		return nil,
			ErrNotificationDeliveryStateConflict
	}

	deliveryStatus := "FAILED"
	var retryAt *time.Time

	if input.RetryAt != nil &&
		attemptCount < maximumAttempts {
		deliveryStatus = "RETRY_SCHEDULED"
		retryAt = input.RetryAt
	}

	updateQuery := `
		UPDATE notification_deliveries d
		SET
			delivery_status = $3,
			last_error = $4,
			provider_response = $5,
			next_retry_at = $6,
			processing_started_at = NULL,
			failed_at = CASE
				WHEN $3 = 'FAILED'
					THEN $7
				ELSE NULL
			END,
			updated_at = $7
		WHERE
			d.id = $1
			AND d.organization_id = $2
		RETURNING ` + notificationDeliveryWorkflowColumns + `;
	`

	delivery, err := scanNotificationDeliveryWorkflow(
		tx.QueryRow(
			ctx,
			updateQuery,
			input.DeliveryID,
			input.OrganizationID,
			deliveryStatus,
			input.LastError,
			providerResponse,
			retryAt,
			input.FailedAt,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"update failed notification delivery: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit notification delivery failure: %w",
			err,
		)
	}

	return delivery, nil
}

func (r *Repository) resolveNotificationDeliveryUpdateError(
	ctx context.Context,
	organizationID uuid.UUID,
	deliveryID uuid.UUID,
) error {
	const query = `
		SELECT delivery_status
		FROM notification_deliveries
		WHERE
			id = $1
			AND organization_id = $2;
	`

	var deliveryStatus string

	err := r.db.QueryRow(
		ctx,
		query,
		deliveryID,
		organizationID,
	).Scan(&deliveryStatus)

	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotificationDeliveryNotFound
	}

	if err != nil {
		return fmt.Errorf(
			"resolve notification delivery state: %w",
			err,
		)
	}

	return fmt.Errorf(
		"%w: current status is %s",
		ErrNotificationDeliveryStateConflict,
		deliveryStatus,
	)
}

func normalizeNotificationDeliveryString(
	value *string,
) *string {
	if value == nil {
		return nil
	}

	normalizedValue := strings.TrimSpace(
		*value,
	)
	if normalizedValue == "" {
		return nil
	}

	return &normalizedValue
}

func normalizeNotificationProviderResponse(
	value json.RawMessage,
) (json.RawMessage, error) {
	trimmedValue := bytes.TrimSpace(value)

	if len(trimmedValue) == 0 {
		return json.RawMessage(`{}`), nil
	}

	if !json.Valid(trimmedValue) {
		return nil,
			ErrInvalidNotificationProviderResponse
	}

	copiedValue := append(
		json.RawMessage(nil),
		trimmedValue...,
	)

	return copiedValue, nil
}

func scanNotificationDeliveryWorkflow(
	scanner notificationDeliveryWorkflowScanner,
) (*Delivery, error) {
	var delivery Delivery

	err := scanner.Scan(
		&delivery.ID,
		&delivery.NotificationID,
		&delivery.RecipientID,
		&delivery.OrganizationID,
		&delivery.Channel,
		&delivery.DeliveryStatus,
		&delivery.AttemptCount,
		&delivery.MaximumAttempts,
		&delivery.ProviderName,
		&delivery.ProviderMessageID,
		&delivery.LastError,
		&delivery.ProviderResponse,
		&delivery.ScheduledAt,
		&delivery.NextRetryAt,
		&delivery.ProcessingStartedAt,
		&delivery.SentAt,
		&delivery.DeliveredAt,
		&delivery.FailedAt,
		&delivery.CreatedAt,
		&delivery.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &delivery, nil
}
