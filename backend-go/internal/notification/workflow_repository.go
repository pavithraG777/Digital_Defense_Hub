package notification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrNotificationAcknowledgementNotRequired = errors.New(
		"notification acknowledgement is not required",
	)
	ErrNotificationDismissalNotAllowed = errors.New(
		"notification requiring acknowledgement cannot be dismissed",
	)
	ErrNotificationExpired = errors.New(
		"notification has expired",
	)
	ErrNotificationCancelled = errors.New(
		"notification has been cancelled",
	)
)

const notificationWorkflowRecipientColumns = `
	nr.id,
	nr.notification_id,
	nr.organization_id,
	nr.recipient_type,
	nr.user_id,
	nr.recipient_name,
	nr.email_address,
	nr.phone_number,
	nr.in_app_status,
	nr.read_at,
	nr.acknowledged_at,
	nr.dismissed_at,
	nr.created_at,
	nr.updated_at
`

type notificationWorkflowScanner interface {
	Scan(dest ...any) error
}

type notificationWorkflowState struct {
	RequiresAcknowledgement bool
	Status                  string
	ExpiresAt               *time.Time
}

func (r *Repository) FindRecipientForUser(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	notificationID uuid.UUID,
) (*Recipient, error) {
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

	if userID == uuid.Nil {
		return nil, errors.New(
			"user ID is required",
		)
	}

	if notificationID == uuid.Nil {
		return nil, errors.New(
			"notification ID is required",
		)
	}

	query := `
		SELECT ` + notificationWorkflowRecipientColumns + `
		FROM notification_recipients nr
		INNER JOIN notifications n
			ON n.id = nr.notification_id
			AND n.organization_id = nr.organization_id
		WHERE
			nr.notification_id = $1
			AND nr.organization_id = $2
			AND nr.user_id = $3
			AND nr.recipient_type = 'USER'
			AND n.deleted_at IS NULL;
	`

	recipient, err := scanNotificationWorkflowRecipient(
		r.db.QueryRow(
			ctx,
			query,
			notificationID,
			organizationID,
			userID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotificationRecipientNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"find notification recipient: %w",
			err,
		)
	}

	return recipient, nil
}

func (r *Repository) MarkRecipientRead(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	notificationID uuid.UUID,
	readAt time.Time,
) (*Recipient, error) {
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

	if userID == uuid.Nil {
		return nil, errors.New(
			"user ID is required",
		)
	}

	if notificationID == uuid.Nil {
		return nil, errors.New(
			"notification ID is required",
		)
	}

	if readAt.IsZero() {
		readAt = time.Now().UTC()
	} else {
		readAt = readAt.UTC()
	}

	query := `
		UPDATE notification_recipients nr
		SET
			in_app_status = CASE
				WHEN nr.in_app_status = 'UNREAD'
					THEN 'READ'
				ELSE nr.in_app_status
			END,
			read_at = COALESCE(
				nr.read_at,
				$4
			),
			updated_at = $4
		FROM notifications n
		WHERE
			n.id = nr.notification_id
			AND n.organization_id = nr.organization_id
			AND nr.notification_id = $1
			AND nr.organization_id = $2
			AND nr.user_id = $3
			AND nr.recipient_type = 'USER'
			AND n.deleted_at IS NULL
		RETURNING ` + notificationWorkflowRecipientColumns + `;
	`

	recipient, err := scanNotificationWorkflowRecipient(
		r.db.QueryRow(
			ctx,
			query,
			notificationID,
			organizationID,
			userID,
			readAt,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotificationRecipientNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"mark notification recipient read: %w",
			err,
		)
	}

	return recipient, nil
}

func (r *Repository) MarkAllRecipientsRead(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	readAt time.Time,
) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New(
			"notification repository is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return 0, errors.New(
			"organization ID is required",
		)
	}

	if userID == uuid.Nil {
		return 0, errors.New(
			"user ID is required",
		)
	}

	if readAt.IsZero() {
		readAt = time.Now().UTC()
	} else {
		readAt = readAt.UTC()
	}

	const query = `
		UPDATE notification_recipients nr
		SET
			in_app_status = 'READ',
			read_at = COALESCE(
				nr.read_at,
				$3
			),
			updated_at = $3
		FROM notifications n
		WHERE
			n.id = nr.notification_id
			AND n.organization_id = nr.organization_id
			AND nr.organization_id = $1
			AND nr.user_id = $2
			AND nr.recipient_type = 'USER'
			AND nr.in_app_status = 'UNREAD'
			AND n.deleted_at IS NULL;
	`

	commandTag, err := r.db.Exec(
		ctx,
		query,
		organizationID,
		userID,
		readAt,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"mark all notification recipients read: %w",
			err,
		)
	}

	return commandTag.RowsAffected(), nil
}

func (r *Repository) AcknowledgeRecipient(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	notificationID uuid.UUID,
	acknowledgedAt time.Time,
) (*Recipient, error) {
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

	if userID == uuid.Nil {
		return nil, errors.New(
			"user ID is required",
		)
	}

	if notificationID == uuid.Nil {
		return nil, errors.New(
			"notification ID is required",
		)
	}

	if acknowledgedAt.IsZero() {
		acknowledgedAt = time.Now().UTC()
	} else {
		acknowledgedAt = acknowledgedAt.UTC()
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin notification acknowledgement transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	state, err := loadNotificationWorkflowState(
		ctx,
		tx,
		organizationID,
		notificationID,
	)
	if err != nil {
		return nil, err
	}

	if err = validateNotificationWorkflowState(
		state,
		acknowledgedAt,
	); err != nil {
		return nil, err
	}

	if !state.RequiresAcknowledgement {
		return nil,
			ErrNotificationAcknowledgementNotRequired
	}

	updateRecipientQuery := `
		UPDATE notification_recipients nr
		SET
			in_app_status = 'ACKNOWLEDGED',
			read_at = COALESCE(
				nr.read_at,
				$4
			),
			acknowledged_at = COALESCE(
				nr.acknowledged_at,
				$4
			),
			dismissed_at = NULL,
			updated_at = $4
		FROM notifications n
		WHERE
			n.id = nr.notification_id
			AND n.organization_id = nr.organization_id
			AND nr.notification_id = $1
			AND nr.organization_id = $2
			AND nr.user_id = $3
			AND nr.recipient_type = 'USER'
			AND n.deleted_at IS NULL
		RETURNING ` + notificationWorkflowRecipientColumns + `;
	`

	recipient, err := scanNotificationWorkflowRecipient(
		tx.QueryRow(
			ctx,
			updateRecipientQuery,
			notificationID,
			organizationID,
			userID,
			acknowledgedAt,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotificationRecipientNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"acknowledge notification recipient: %w",
			err,
		)
	}

	const updateNotificationQuery = `
		UPDATE notifications
		SET
			acknowledged_by = COALESCE(
				acknowledged_by,
				$3
			),
			acknowledged_at = COALESCE(
				acknowledged_at,
				$4
			),
			updated_at = $4
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL;
	`

	if _, err = tx.Exec(
		ctx,
		updateNotificationQuery,
		notificationID,
		organizationID,
		userID,
		acknowledgedAt,
	); err != nil {
		return nil, fmt.Errorf(
			"update notification acknowledgement: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit notification acknowledgement: %w",
			err,
		)
	}

	return recipient, nil
}

func (r *Repository) DismissRecipient(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	notificationID uuid.UUID,
	dismissedAt time.Time,
) (*Recipient, error) {
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

	if userID == uuid.Nil {
		return nil, errors.New(
			"user ID is required",
		)
	}

	if notificationID == uuid.Nil {
		return nil, errors.New(
			"notification ID is required",
		)
	}

	if dismissedAt.IsZero() {
		dismissedAt = time.Now().UTC()
	} else {
		dismissedAt = dismissedAt.UTC()
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"begin notification dismissal transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	state, err := loadNotificationWorkflowState(
		ctx,
		tx,
		organizationID,
		notificationID,
	)
	if err != nil {
		return nil, err
	}

	if err = validateNotificationWorkflowState(
		state,
		dismissedAt,
	); err != nil {
		return nil, err
	}

	if state.RequiresAcknowledgement {
		return nil, ErrNotificationDismissalNotAllowed
	}

	updateQuery := `
		UPDATE notification_recipients nr
		SET
			in_app_status = 'DISMISSED',
			read_at = COALESCE(
				nr.read_at,
				$4
			),
			dismissed_at = COALESCE(
				nr.dismissed_at,
				$4
			),
			updated_at = $4
		FROM notifications n
		WHERE
			n.id = nr.notification_id
			AND n.organization_id = nr.organization_id
			AND nr.notification_id = $1
			AND nr.organization_id = $2
			AND nr.user_id = $3
			AND nr.recipient_type = 'USER'
			AND n.deleted_at IS NULL
		RETURNING ` + notificationWorkflowRecipientColumns + `;
	`

	recipient, err := scanNotificationWorkflowRecipient(
		tx.QueryRow(
			ctx,
			updateQuery,
			notificationID,
			organizationID,
			userID,
			dismissedAt,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotificationRecipientNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"dismiss notification recipient: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit notification dismissal: %w",
			err,
		)
	}

	return recipient, nil
}

func loadNotificationWorkflowState(
	ctx context.Context,
	tx pgx.Tx,
	organizationID uuid.UUID,
	notificationID uuid.UUID,
) (*notificationWorkflowState, error) {
	const query = `
		SELECT
			requires_acknowledgement,
			status,
			expires_at
		FROM notifications
		WHERE
			id = $1
			AND organization_id = $2
			AND deleted_at IS NULL
		FOR UPDATE;
	`

	var state notificationWorkflowState

	err := tx.QueryRow(
		ctx,
		query,
		notificationID,
		organizationID,
	).Scan(
		&state.RequiresAcknowledgement,
		&state.Status,
		&state.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotificationNotFound
	}

	if err != nil {
		return nil, fmt.Errorf(
			"load notification workflow state: %w",
			err,
		)
	}

	return &state, nil
}

func validateNotificationWorkflowState(
	state *notificationWorkflowState,
	occurredAt time.Time,
) error {
	if state == nil {
		return ErrNotificationNotFound
	}

	switch state.Status {
	case "CANCELLED":
		return ErrNotificationCancelled

	case "EXPIRED":
		return ErrNotificationExpired
	}

	if state.ExpiresAt != nil &&
		!state.ExpiresAt.After(occurredAt) {
		return ErrNotificationExpired
	}

	return nil
}

func scanNotificationWorkflowRecipient(
	scanner notificationWorkflowScanner,
) (*Recipient, error) {
	var recipient Recipient

	err := scanner.Scan(
		&recipient.ID,
		&recipient.NotificationID,
		&recipient.OrganizationID,
		&recipient.RecipientType,
		&recipient.UserID,
		&recipient.RecipientName,
		&recipient.EmailAddress,
		&recipient.PhoneNumber,
		&recipient.InAppStatus,
		&recipient.ReadAt,
		&recipient.AcknowledgedAt,
		&recipient.DismissedAt,
		&recipient.CreatedAt,
		&recipient.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &recipient, nil
}
