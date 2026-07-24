package notification

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotificationNotFound = errors.New(
		"notification not found",
	)
	ErrNotificationCodeExists = errors.New(
		"notification code already exists",
	)
	ErrNotificationDuplicate = errors.New(
		"duplicate notification",
	)
	ErrNotificationReferenceNotFound = errors.New(
		"notification reference not found",
	)
	ErrNotificationRecipientNotFound = errors.New(
		"notification recipient not found",
	)
)

const notificationSelectColumns = `
	id,
	notification_sequence,
	notification_code,
	organization_id,
	department_id,
	incident_id,
	threat_id,
	notification_type,
	category,
	title,
	message,
	severity,
	priority_level,
	deduplication_key,
	payload,
	requires_acknowledgement,
	acknowledged_by,
	acknowledged_at,
	status,
	created_by,
	scheduled_at,
	expires_at,
	created_at,
	updated_at,
	deleted_at
`

const recipientSelectColumns = `
	id,
	notification_id,
	organization_id,
	recipient_type,
	user_id,
	recipient_name,
	email_address,
	phone_number,
	in_app_status,
	read_at,
	acknowledged_at,
	dismissed_at,
	created_at,
	updated_at
`

const deliverySelectColumns = `
	id,
	notification_id,
	recipient_id,
	organization_id,
	channel,
	delivery_status,
	attempt_count,
	maximum_attempts,
	provider_name,
	provider_message_id,
	last_error,
	provider_response,
	scheduled_at,
	next_retry_at,
	processing_started_at,
	sent_at,
	delivered_at,
	failed_at,
	created_at,
	updated_at
`

// Repository manages notification persistence.
type Repository struct {
	db *pgxpool.Pool
}

type rowScanner interface {
	Scan(dest ...any) error
}

func NewRepository(
	db *pgxpool.Pool,
) *Repository {
	return &Repository{
		db: db,
	}
}

// Create atomically creates a notification, recipients and deliveries.
func (r *Repository) Create(
	ctx context.Context,
	notification *Notification,
	recipients []*Recipient,
	deliveries []*Delivery,
) error {
	if r == nil || r.db == nil {
		return errors.New(
			"notification repository is unavailable",
		)
	}

	if notification == nil {
		return errors.New(
			"notification is required",
		)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"begin notification transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	err = validateNotificationReferencesTx(
		ctx,
		tx,
		notification,
	)
	if err != nil {
		return err
	}

	const notificationQuery = `
		INSERT INTO notifications (
			id,
			notification_code,
			organization_id,
			department_id,
			incident_id,
			threat_id,
			notification_type,
			category,
			title,
			message,
			severity,
			priority_level,
			deduplication_key,
			payload,
			requires_acknowledgement,
			acknowledged_by,
			acknowledged_at,
			status,
			created_by,
			scheduled_at,
			expires_at
		)
		VALUES (
			$1,$2,$3,$4,$5,$6,$7,
			$8,$9,$10,$11,$12,$13,$14,
			$15,$16,$17,$18,$19,$20,$21
		)
		RETURNING
			notification_sequence,
			created_at,
			updated_at;
	`

	err = tx.QueryRow(
		ctx,
		notificationQuery,
		notification.ID,
		notification.NotificationCode,
		notification.OrganizationID,
		notification.DepartmentID,
		notification.IncidentID,
		notification.ThreatID,
		notification.NotificationType,
		notification.Category,
		notification.Title,
		notification.Message,
		notification.Severity,
		notification.PriorityLevel,
		notification.DeduplicationKey,
		notification.Payload,
		notification.RequiresAcknowledgement,
		notification.AcknowledgedBy,
		notification.AcknowledgedAt,
		notification.Status,
		notification.CreatedBy,
		notification.ScheduledAt,
		notification.ExpiresAt,
	).Scan(
		&notification.NotificationSequence,
		&notification.CreatedAt,
		&notification.UpdatedAt,
	)
	if err != nil {
		if isNotificationConstraintViolation(
			err,
			"uq_notification_code",
		) {
			return ErrNotificationCodeExists
		}

		if isNotificationConstraintViolation(
			err,
			"uq_notification_deduplication",
		) {
			return ErrNotificationDuplicate
		}

		return fmt.Errorf(
			"create notification: %w",
			err,
		)
	}

	for _, recipient := range recipients {
		if recipient == nil {
			return errors.New(
				"notification recipient is required",
			)
		}

		recipient.NotificationID = notification.ID
		recipient.OrganizationID =
			notification.OrganizationID

		err = validateNotificationRecipientTx(
			ctx,
			tx,
			recipient,
		)
		if err != nil {
			return err
		}

		const recipientQuery = `
			INSERT INTO notification_recipients (
				id,
				notification_id,
				organization_id,
				recipient_type,
				user_id,
				recipient_name,
				email_address,
				phone_number,
				in_app_status,
				read_at,
				acknowledged_at,
				dismissed_at
			)
			VALUES (
				$1,$2,$3,$4,$5,$6,
				$7,$8,$9,$10,$11,$12
			)
			RETURNING
				created_at,
				updated_at;
		`

		err = tx.QueryRow(
			ctx,
			recipientQuery,
			recipient.ID,
			recipient.NotificationID,
			recipient.OrganizationID,
			recipient.RecipientType,
			recipient.UserID,
			recipient.RecipientName,
			recipient.EmailAddress,
			recipient.PhoneNumber,
			recipient.InAppStatus,
			recipient.ReadAt,
			recipient.AcknowledgedAt,
			recipient.DismissedAt,
		).Scan(
			&recipient.CreatedAt,
			&recipient.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf(
				"create notification recipient: %w",
				err,
			)
		}
	}

	for _, delivery := range deliveries {
		if delivery == nil {
			return errors.New(
				"notification delivery is required",
			)
		}

		delivery.NotificationID = notification.ID
		delivery.OrganizationID =
			notification.OrganizationID

		const deliveryQuery = `
			INSERT INTO notification_deliveries (
				id,
				notification_id,
				recipient_id,
				organization_id,
				channel,
				delivery_status,
				attempt_count,
				maximum_attempts,
				provider_name,
				provider_message_id,
				last_error,
				provider_response,
				scheduled_at,
				next_retry_at,
				processing_started_at,
				sent_at,
				delivered_at,
				failed_at
			)
			SELECT
				$1,$2,nr.id,$3,$4,$5,$6,$7,
				$8,$9,$10,$11,$12,$13,$14,
				$15,$16,$17
			FROM notification_recipients nr
			WHERE nr.id = $18
			  AND nr.notification_id = $2
			  AND nr.organization_id = $3
			RETURNING
				created_at,
				updated_at;
		`

		err = tx.QueryRow(
			ctx,
			deliveryQuery,
			delivery.ID,
			notification.ID,
			notification.OrganizationID,
			delivery.Channel,
			delivery.DeliveryStatus,
			delivery.AttemptCount,
			delivery.MaximumAttempts,
			delivery.ProviderName,
			delivery.ProviderMessageID,
			delivery.LastError,
			delivery.ProviderResponse,
			delivery.ScheduledAt,
			delivery.NextRetryAt,
			delivery.ProcessingStartedAt,
			delivery.SentAt,
			delivery.DeliveredAt,
			delivery.FailedAt,
			delivery.RecipientID,
		).Scan(
			&delivery.CreatedAt,
			&delivery.UpdatedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotificationRecipientNotFound
		}
		if err != nil {
			return fmt.Errorf(
				"create notification delivery: %w",
				err,
			)
		}
	}

	returnedStatus := notification.Status

	if len(deliveries) > 0 {
		returnedStatus = StatusQueued
	}

	err = tx.QueryRow(
		ctx,
		`
			UPDATE notifications
			SET
				status = $2::varchar,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = $1
			RETURNING
				status,
				updated_at;
		`,
		notification.ID,
		returnedStatus,
	).Scan(
		&notification.Status,
		&notification.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"queue notification: %w",
			err,
		)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit notification transaction: %w",
			err,
		)
	}

	return nil
}

// FindByID returns one organization notification.
func (r *Repository) FindByID(
	ctx context.Context,
	organizationID uuid.UUID,
	notificationID uuid.UUID,
) (*Notification, error) {
	if r == nil || r.db == nil {
		return nil, errors.New(
			"notification repository is unavailable",
		)
	}

	query := `
		SELECT ` + notificationSelectColumns + `
		FROM notifications
		WHERE id = $1
		  AND organization_id = $2
		  AND deleted_at IS NULL;
	`

	notification, err := scanNotification(
		r.db.QueryRow(
			ctx,
			query,
			notificationID,
			organizationID,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotificationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"find notification: %w",
			err,
		)
	}

	return notification, nil
}

// FindByDeduplicationKey returns an existing matching notification.
func (r *Repository) FindByDeduplicationKey(
	ctx context.Context,
	organizationID uuid.UUID,
	deduplicationKey string,
) (*Notification, error) {
	query := `
		SELECT ` + notificationSelectColumns + `
		FROM notifications
		WHERE organization_id = $1
		  AND deduplication_key = $2
		  AND deleted_at IS NULL;
	`

	notification, err := scanNotification(
		r.db.QueryRow(
			ctx,
			query,
			organizationID,
			deduplicationKey,
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotificationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"find notification by deduplication key: %w",
			err,
		)
	}

	return notification, nil
}

// ListRecipients returns notification recipients.
func (r *Repository) ListRecipients(
	ctx context.Context,
	organizationID uuid.UUID,
	notificationID uuid.UUID,
) ([]Recipient, error) {
	query := `
		SELECT ` + recipientSelectColumns + `
		FROM notification_recipients
		WHERE notification_id = $1
		  AND organization_id = $2
		ORDER BY created_at ASC;
	`

	rows, err := r.db.Query(
		ctx,
		query,
		notificationID,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list notification recipients: %w",
			err,
		)
	}
	defer rows.Close()

	recipients := make(
		[]Recipient,
		0,
	)

	for rows.Next() {
		recipient, scanErr := scanRecipient(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan notification recipient: %w",
				scanErr,
			)
		}

		recipients = append(
			recipients,
			*recipient,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate notification recipients: %w",
			err,
		)
	}

	return recipients, nil
}

// ListDeliveries returns channel delivery records.
func (r *Repository) ListDeliveries(
	ctx context.Context,
	organizationID uuid.UUID,
	notificationID uuid.UUID,
) ([]Delivery, error) {
	query := `
		SELECT ` + deliverySelectColumns + `
		FROM notification_deliveries
		WHERE notification_id = $1
		  AND organization_id = $2
		ORDER BY created_at ASC;
	`

	rows, err := r.db.Query(
		ctx,
		query,
		notificationID,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list notification deliveries: %w",
			err,
		)
	}
	defer rows.Close()

	deliveries := make(
		[]Delivery,
		0,
	)

	for rows.Next() {
		delivery, scanErr := scanDelivery(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan notification delivery: %w",
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
			"iterate notification deliveries: %w",
			err,
		)
	}

	return deliveries, nil
}

func validateNotificationReferencesTx(
	ctx context.Context,
	tx pgx.Tx,
	notification *Notification,
) error {
	var (
		departmentValid bool
		incidentValid   bool
		threatValid     bool
		creatorValid    bool
	)

	const query = `
		SELECT
			(
				$1::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM departments
					WHERE id = $1
					  AND organization_id = $5
					  AND deleted_at IS NULL
				)
			),
			(
				$2::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM incidents
					WHERE id = $2
					  AND organization_id = $5
					  AND deleted_at IS NULL
				)
			),
			(
				$3::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM threats
					WHERE id = $3
					  AND organization_id = $5
					  AND deleted_at IS NULL
				)
			),
			(
				$4::uuid IS NULL
				OR EXISTS (
					SELECT 1
					FROM users
					WHERE id = $4
					  AND organization_id = $5
					  AND deleted_at IS NULL
				)
			);
	`

	err := tx.QueryRow(
		ctx,
		query,
		notification.DepartmentID,
		notification.IncidentID,
		notification.ThreatID,
		notification.CreatedBy,
		notification.OrganizationID,
	).Scan(
		&departmentValid,
		&incidentValid,
		&threatValid,
		&creatorValid,
	)
	if err != nil {
		return fmt.Errorf(
			"validate notification references: %w",
			err,
		)
	}

	if !departmentValid ||
		!incidentValid ||
		!threatValid ||
		!creatorValid {
		return ErrNotificationReferenceNotFound
	}

	return nil
}

func validateNotificationRecipientTx(
	ctx context.Context,
	tx pgx.Tx,
	recipient *Recipient,
) error {
	if recipient.UserID == nil {
		return nil
	}

	var valid bool

	err := tx.QueryRow(
		ctx,
		`
			SELECT EXISTS (
				SELECT 1
				FROM users
				WHERE id = $1
				  AND organization_id = $2
				  AND deleted_at IS NULL
			);
		`,
		recipient.UserID,
		recipient.OrganizationID,
	).Scan(
		&valid,
	)
	if err != nil {
		return fmt.Errorf(
			"validate notification recipient: %w",
			err,
		)
	}

	if !valid {
		return ErrNotificationRecipientNotFound
	}

	return nil
}

func scanNotification(
	scanner rowScanner,
) (*Notification, error) {
	notification := &Notification{}

	err := scanner.Scan(
		&notification.ID,
		&notification.NotificationSequence,
		&notification.NotificationCode,
		&notification.OrganizationID,
		&notification.DepartmentID,
		&notification.IncidentID,
		&notification.ThreatID,
		&notification.NotificationType,
		&notification.Category,
		&notification.Title,
		&notification.Message,
		&notification.Severity,
		&notification.PriorityLevel,
		&notification.DeduplicationKey,
		&notification.Payload,
		&notification.RequiresAcknowledgement,
		&notification.AcknowledgedBy,
		&notification.AcknowledgedAt,
		&notification.Status,
		&notification.CreatedBy,
		&notification.ScheduledAt,
		&notification.ExpiresAt,
		&notification.CreatedAt,
		&notification.UpdatedAt,
		&notification.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	return notification, nil
}

func scanRecipient(
	scanner rowScanner,
) (*Recipient, error) {
	recipient := &Recipient{}

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

	return recipient, nil
}

func scanDelivery(
	scanner rowScanner,
) (*Delivery, error) {
	delivery := &Delivery{}

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

	return delivery, nil
}

func isNotificationConstraintViolation(
	err error,
	constraintName string,
) bool {
	var pgError *pgconn.PgError

	if !errors.As(err, &pgError) {
		return false
	}

	return pgError.Code == "23505" &&
		pgError.ConstraintName == constraintName
}
