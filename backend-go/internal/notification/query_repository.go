package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const notificationQuerySelectColumns = `
	n.id,
	n.notification_sequence,
	n.notification_code,
	n.organization_id,
	n.department_id,
	n.incident_id,
	n.threat_id,
	n.notification_type,
	n.category,
	n.title,
	n.message,
	n.severity,
	n.priority_level,
	n.deduplication_key,
	n.payload,
	n.requires_acknowledgement,
	n.acknowledged_by,
	n.acknowledged_at,
	n.status,
	n.created_by,
	n.scheduled_at,
	n.expires_at,
	n.created_at,
	n.updated_at,
	n.deleted_at
`

type NotificationFilter struct {
	OrganizationID uuid.UUID
	DepartmentID   *uuid.UUID
	IncidentID     *uuid.UUID
	ThreatID       *uuid.UUID

	NotificationType string
	Category         string
	Severity         string
	Status           string
	Search           string

	From *time.Time
	To   *time.Time

	Limit  int
	Offset int
}

type UserNotificationFilter struct {
	OrganizationID uuid.UUID
	UserID         uuid.UUID

	NotificationType string
	Category         string
	Severity         string
	InAppStatus      string
	Search           string

	From *time.Time
	To   *time.Time

	Limit  int
	Offset int
}

type UserNotificationRecord struct {
	Notification Notification

	RecipientID    uuid.UUID
	InAppStatus    string
	ReadAt         *time.Time
	AcknowledgedAt *time.Time
	DismissedAt    *time.Time
}

type notificationQueryScanner interface {
	Scan(dest ...any) error
}

func (r *Repository) List(
	ctx context.Context,
	filter NotificationFilter,
) ([]Notification, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New(
			"notification repository is unavailable",
		)
	}

	if filter.OrganizationID == uuid.Nil {
		return nil, 0, errors.New(
			"organization ID is required",
		)
	}

	args := []any{
		filter.OrganizationID,
	}

	conditions := []string{
		"n.organization_id = $1",
		"n.deleted_at IS NULL",
	}

	addCondition := func(
		condition string,
		value any,
	) {
		args = append(args, value)

		conditions = append(
			conditions,
			fmt.Sprintf(
				condition,
				len(args),
			),
		)
	}

	if filter.DepartmentID != nil {
		addCondition(
			"n.department_id = $%d",
			*filter.DepartmentID,
		)
	}

	if filter.IncidentID != nil {
		addCondition(
			"n.incident_id = $%d",
			*filter.IncidentID,
		)
	}

	if filter.ThreatID != nil {
		addCondition(
			"n.threat_id = $%d",
			*filter.ThreatID,
		)
	}

	if filter.NotificationType != "" {
		addCondition(
			"n.notification_type = $%d",
			filter.NotificationType,
		)
	}

	if filter.Category != "" {
		addCondition(
			"n.category = $%d",
			filter.Category,
		)
	}

	if filter.Severity != "" {
		addCondition(
			"n.severity = $%d",
			filter.Severity,
		)
	}

	if filter.Status != "" {
		addCondition(
			"n.status = $%d",
			filter.Status,
		)
	}

	if filter.Search != "" {
		searchValue := "%" +
			strings.TrimSpace(filter.Search) +
			"%"

		args = append(
			args,
			searchValue,
			searchValue,
			searchValue,
		)

		conditions = append(
			conditions,
			fmt.Sprintf(
				`(
					n.notification_code ILIKE $%d
					OR n.title ILIKE $%d
					OR n.message ILIKE $%d
				)`,
				len(args)-2,
				len(args)-1,
				len(args),
			),
		)
	}

	if filter.From != nil {
		addCondition(
			"n.created_at >= $%d",
			*filter.From,
		)
	}

	if filter.To != nil {
		addCondition(
			"n.created_at <= $%d",
			*filter.To,
		)
	}

	whereClause := strings.Join(
		conditions,
		" AND ",
	)

	countQuery := `
		SELECT COUNT(*)
		FROM notifications n
		WHERE ` + whereClause + `;
	`

	var total int64

	if err := r.db.QueryRow(
		ctx,
		countQuery,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf(
			"count notifications: %w",
			err,
		)
	}

	limit, offset := normalizeNotificationPagination(
		filter.Limit,
		filter.Offset,
	)

	listArgs := append(
		[]any{},
		args...,
	)

	listArgs = append(
		listArgs,
		limit,
		offset,
	)

	limitPosition := len(listArgs) - 1
	offsetPosition := len(listArgs)

	listQuery := `
		SELECT ` + notificationQuerySelectColumns + `
		FROM notifications n
		WHERE ` + whereClause + `
		ORDER BY
			n.created_at DESC,
			n.notification_sequence DESC
		LIMIT $` + fmt.Sprintf(
		"%d",
		limitPosition,
	) + `
		OFFSET $` + fmt.Sprintf(
		"%d",
		offsetPosition,
	) + `;
	`

	rows, err := r.db.Query(
		ctx,
		listQuery,
		listArgs...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf(
			"list notifications: %w",
			err,
		)
	}
	defer rows.Close()

	notifications := make(
		[]Notification,
		0,
		limit,
	)

	for rows.Next() {
		notificationRecord, scanErr :=
			scanNotificationQuery(rows)
		if scanErr != nil {
			return nil, 0, fmt.Errorf(
				"scan listed notification: %w",
				scanErr,
			)
		}

		notifications = append(
			notifications,
			*notificationRecord,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf(
			"iterate notifications: %w",
			err,
		)
	}

	return notifications, total, nil
}

func (r *Repository) ListForUser(
	ctx context.Context,
	filter UserNotificationFilter,
) ([]UserNotificationRecord, int64, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, 0, errors.New(
			"notification repository is unavailable",
		)
	}

	if filter.OrganizationID == uuid.Nil {
		return nil, 0, 0, errors.New(
			"organization ID is required",
		)
	}

	if filter.UserID == uuid.Nil {
		return nil, 0, 0, errors.New(
			"user ID is required",
		)
	}

	args := []any{
		filter.OrganizationID,
		filter.UserID,
	}

	conditions := []string{
		"n.organization_id = $1",
		"nr.organization_id = $1",
		"nr.user_id = $2",
		"nr.recipient_type = 'USER'",
		"n.deleted_at IS NULL",
	}

	addCondition := func(
		condition string,
		value any,
	) {
		args = append(args, value)

		conditions = append(
			conditions,
			fmt.Sprintf(
				condition,
				len(args),
			),
		)
	}

	if filter.NotificationType != "" {
		addCondition(
			"n.notification_type = $%d",
			filter.NotificationType,
		)
	}

	if filter.Category != "" {
		addCondition(
			"n.category = $%d",
			filter.Category,
		)
	}

	if filter.Severity != "" {
		addCondition(
			"n.severity = $%d",
			filter.Severity,
		)
	}

	if filter.InAppStatus != "" {
		addCondition(
			"nr.in_app_status = $%d",
			filter.InAppStatus,
		)
	}

	if filter.Search != "" {
		searchValue := "%" +
			strings.TrimSpace(filter.Search) +
			"%"

		args = append(
			args,
			searchValue,
			searchValue,
			searchValue,
		)

		conditions = append(
			conditions,
			fmt.Sprintf(
				`(
					n.notification_code ILIKE $%d
					OR n.title ILIKE $%d
					OR n.message ILIKE $%d
				)`,
				len(args)-2,
				len(args)-1,
				len(args),
			),
		)
	}

	if filter.From != nil {
		addCondition(
			"n.created_at >= $%d",
			*filter.From,
		)
	}

	if filter.To != nil {
		addCondition(
			"n.created_at <= $%d",
			*filter.To,
		)
	}

	whereClause := strings.Join(
		conditions,
		" AND ",
	)

	countQuery := `
		SELECT COUNT(*)
		FROM notification_recipients nr
		INNER JOIN notifications n
			ON n.id = nr.notification_id
			AND n.organization_id = nr.organization_id
		WHERE ` + whereClause + `;
	`

	var total int64

	if err := r.db.QueryRow(
		ctx,
		countQuery,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, 0, fmt.Errorf(
			"count user notifications: %w",
			err,
		)
	}

	const unreadCountQuery = `
		SELECT COUNT(*)
		FROM notification_recipients nr
		INNER JOIN notifications n
			ON n.id = nr.notification_id
			AND n.organization_id = nr.organization_id
		WHERE
			nr.organization_id = $1
			AND nr.user_id = $2
			AND nr.recipient_type = 'USER'
			AND nr.in_app_status = 'UNREAD'
			AND n.deleted_at IS NULL;
	`

	var unreadTotal int64

	if err := r.db.QueryRow(
		ctx,
		unreadCountQuery,
		filter.OrganizationID,
		filter.UserID,
	).Scan(&unreadTotal); err != nil {
		return nil, 0, 0, fmt.Errorf(
			"count unread notifications: %w",
			err,
		)
	}

	limit, offset := normalizeNotificationPagination(
		filter.Limit,
		filter.Offset,
	)

	listArgs := append(
		[]any{},
		args...,
	)

	listArgs = append(
		listArgs,
		limit,
		offset,
	)

	limitPosition := len(listArgs) - 1
	offsetPosition := len(listArgs)

	listQuery := `
		SELECT
			` + notificationQuerySelectColumns + `,
			nr.id,
			nr.in_app_status,
			nr.read_at,
			nr.acknowledged_at,
			nr.dismissed_at
		FROM notification_recipients nr
		INNER JOIN notifications n
			ON n.id = nr.notification_id
			AND n.organization_id = nr.organization_id
		WHERE ` + whereClause + `
		ORDER BY
			n.created_at DESC,
			n.notification_sequence DESC
		LIMIT $` + fmt.Sprintf(
		"%d",
		limitPosition,
	) + `
		OFFSET $` + fmt.Sprintf(
		"%d",
		offsetPosition,
	) + `;
	`

	rows, err := r.db.Query(
		ctx,
		listQuery,
		listArgs...,
	)
	if err != nil {
		return nil, 0, 0, fmt.Errorf(
			"list user notifications: %w",
			err,
		)
	}
	defer rows.Close()

	records := make(
		[]UserNotificationRecord,
		0,
		limit,
	)

	for rows.Next() {
		record, scanErr :=
			scanUserNotificationQuery(rows)
		if scanErr != nil {
			return nil, 0, 0, fmt.Errorf(
				"scan user notification: %w",
				scanErr,
			)
		}

		records = append(
			records,
			*record,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, 0, fmt.Errorf(
			"iterate user notifications: %w",
			err,
		)
	}

	return records, total, unreadTotal, nil
}

func normalizeNotificationPagination(
	limit int,
	offset int,
) (int, int) {
	if limit <= 0 {
		limit = 20
	}

	if limit > 100 {
		limit = 100
	}

	if offset < 0 {
		offset = 0
	}

	return limit, offset
}

func scanNotificationQuery(
	scanner notificationQueryScanner,
) (*Notification, error) {
	var notificationRecord Notification

	err := scanner.Scan(
		&notificationRecord.ID,
		&notificationRecord.NotificationSequence,
		&notificationRecord.NotificationCode,
		&notificationRecord.OrganizationID,
		&notificationRecord.DepartmentID,
		&notificationRecord.IncidentID,
		&notificationRecord.ThreatID,
		&notificationRecord.NotificationType,
		&notificationRecord.Category,
		&notificationRecord.Title,
		&notificationRecord.Message,
		&notificationRecord.Severity,
		&notificationRecord.PriorityLevel,
		&notificationRecord.DeduplicationKey,
		&notificationRecord.Payload,
		&notificationRecord.RequiresAcknowledgement,
		&notificationRecord.AcknowledgedBy,
		&notificationRecord.AcknowledgedAt,
		&notificationRecord.Status,
		&notificationRecord.CreatedBy,
		&notificationRecord.ScheduledAt,
		&notificationRecord.ExpiresAt,
		&notificationRecord.CreatedAt,
		&notificationRecord.UpdatedAt,
		&notificationRecord.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	return &notificationRecord, nil
}

func scanUserNotificationQuery(
	scanner notificationQueryScanner,
) (*UserNotificationRecord, error) {
	var record UserNotificationRecord

	err := scanner.Scan(
		&record.Notification.ID,
		&record.Notification.NotificationSequence,
		&record.Notification.NotificationCode,
		&record.Notification.OrganizationID,
		&record.Notification.DepartmentID,
		&record.Notification.IncidentID,
		&record.Notification.ThreatID,
		&record.Notification.NotificationType,
		&record.Notification.Category,
		&record.Notification.Title,
		&record.Notification.Message,
		&record.Notification.Severity,
		&record.Notification.PriorityLevel,
		&record.Notification.DeduplicationKey,
		&record.Notification.Payload,
		&record.Notification.RequiresAcknowledgement,
		&record.Notification.AcknowledgedBy,
		&record.Notification.AcknowledgedAt,
		&record.Notification.Status,
		&record.Notification.CreatedBy,
		&record.Notification.ScheduledAt,
		&record.Notification.ExpiresAt,
		&record.Notification.CreatedAt,
		&record.Notification.UpdatedAt,
		&record.Notification.DeletedAt,
		&record.RecipientID,
		&record.InAppStatus,
		&record.ReadAt,
		&record.AcknowledgedAt,
		&record.DismissedAt,
	)
	if err != nil {
		return nil, err
	}

	return &record, nil
}
