package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrAuditLogCreationFailed = errors.New(
	"failed to create audit log",
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(
	db *pgxpool.Pool,
) *Repository {
	return &Repository{
		db: db,
	}
}

func (r *Repository) Create(
	ctx context.Context,
	auditLog *AuditLog,
) error {
	if auditLog == nil {
		return fmt.Errorf(
			"%w: audit log cannot be nil",
			ErrAuditLogCreationFailed,
		)
	}

	oldValuesJSON, err := marshalJSON(
		auditLog.OldValues,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: failed to encode old values: %v",
			ErrAuditLogCreationFailed,
			err,
		)
	}

	newValuesJSON, err := marshalJSON(
		auditLog.NewValues,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: failed to encode new values: %v",
			ErrAuditLogCreationFailed,
			err,
		)
	}

	metadataJSON, err := marshalJSON(
		auditLog.Metadata,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: failed to encode metadata: %v",
			ErrAuditLogCreationFailed,
			err,
		)
	}

	if auditLog.OccurredAt.IsZero() {
		auditLog.OccurredAt = time.Now().UTC()
	}

	const query = `
		INSERT INTO audit_logs (
			organization_id,
			user_id,
			session_id,
			module_name,
			action_name,
			entity_type,
			entity_id,
			description,
			old_values,
			new_values,
			metadata,
			ip_address,
			device_name,
			user_agent,
			result_status,
			risk_level,
			failure_reason,
			occurred_at
		)
		VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9::jsonb,
			$10::jsonb,
			$11::jsonb,
			$12,
			$13,
			$14,
			$15,
			$16,
			$17,
			$18
		)
		RETURNING
			id,
			occurred_at,
			created_at
	`

	err = r.db.QueryRow(
		ctx,
		query,
		auditLog.OrganizationID,
		auditLog.UserID,
		auditLog.SessionID,
		strings.ToUpper(
			strings.TrimSpace(auditLog.ModuleName),
		),
		strings.ToUpper(
			strings.TrimSpace(auditLog.ActionName),
		),
		nullableString(auditLog.EntityType),
		auditLog.EntityID,
		nullableString(auditLog.Description),
		oldValuesJSON,
		newValuesJSON,
		metadataJSON,
		nullableString(auditLog.IPAddress),
		nullableString(auditLog.DeviceName),
		nullableString(auditLog.UserAgent),
		strings.ToUpper(
			strings.TrimSpace(auditLog.ResultStatus),
		),
		strings.ToUpper(
			strings.TrimSpace(auditLog.RiskLevel),
		),
		nullableString(auditLog.FailureReason),
		auditLog.OccurredAt,
	).Scan(
		&auditLog.ID,
		&auditLog.OccurredAt,
		&auditLog.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"%w: %v",
			ErrAuditLogCreationFailed,
			err,
		)
	}

	return nil
}

func (r *Repository) List(
	ctx context.Context,
) ([]AuditLog, error) {

	const query = `
	SELECT
		id,
		organization_id,
		user_id,
		session_id,
		module_name,
		action_name,
		entity_type,
		entity_id,
		description,
		old_values,
		new_values,
		metadata,
		COALESCE(ip_address::text, ''),
		COALESCE(device_name, ''),
		COALESCE(user_agent, ''),
		result_status,
		risk_level,
		COALESCE(failure_reason, ''),
		occurred_at,
		created_at
	FROM audit_logs
	ORDER BY occurred_at DESC
`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var auditLogs []AuditLog

	for rows.Next() {

		var auditLog AuditLog

		var oldValues []byte
		var newValues []byte
		var metadata []byte

		err := rows.Scan(
			&auditLog.ID,
			&auditLog.OrganizationID,
			&auditLog.UserID,
			&auditLog.SessionID,
			&auditLog.ModuleName,
			&auditLog.ActionName,
			&auditLog.EntityType,
			&auditLog.EntityID,
			&auditLog.Description,
			&oldValues,
			&newValues,
			&metadata,
			&auditLog.IPAddress,
			&auditLog.DeviceName,
			&auditLog.UserAgent,
			&auditLog.ResultStatus,
			&auditLog.RiskLevel,
			&auditLog.FailureReason,
			&auditLog.OccurredAt,
			&auditLog.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		_ = json.Unmarshal(oldValues, &auditLog.OldValues)
		_ = json.Unmarshal(newValues, &auditLog.NewValues)
		_ = json.Unmarshal(metadata, &auditLog.Metadata)

		auditLogs = append(auditLogs, auditLog)
	}

	return auditLogs, nil
}

func (r *Repository) GetByID(
	ctx context.Context,
	id string,
) (*AuditLog, error) {

	const query = `
	SELECT
		id,
		organization_id,
		user_id,
		session_id,
		module_name,
		action_name,
		entity_type,
		entity_id,
		description,
		old_values,
		new_values,
		metadata,
		COALESCE(ip_address::text, ''),
		COALESCE(device_name, ''),
		COALESCE(user_agent, ''),
		result_status,
		risk_level,
		COALESCE(failure_reason, ''),
		occurred_at,
		created_at
	FROM audit_logs
	WHERE id = $1
`

	var auditLog AuditLog

	var oldValues []byte
	var newValues []byte
	var metadata []byte

	err := r.db.QueryRow(
		ctx,
		query,
		id,
	).Scan(
		&auditLog.ID,
		&auditLog.OrganizationID,
		&auditLog.UserID,
		&auditLog.SessionID,
		&auditLog.ModuleName,
		&auditLog.ActionName,
		&auditLog.EntityType,
		&auditLog.EntityID,
		&auditLog.Description,
		&oldValues,
		&newValues,
		&metadata,
		&auditLog.IPAddress,
		&auditLog.DeviceName,
		&auditLog.UserAgent,
		&auditLog.ResultStatus,
		&auditLog.RiskLevel,
		&auditLog.FailureReason,
		&auditLog.OccurredAt,
		&auditLog.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	_ = json.Unmarshal(oldValues, &auditLog.OldValues)
	_ = json.Unmarshal(newValues, &auditLog.NewValues)
	_ = json.Unmarshal(metadata, &auditLog.Metadata)

	return &auditLog, nil
}

func marshalJSON(
	value map[string]any,
) ([]byte, error) {
	if value == nil {
		return []byte(`{}`), nil
	}

	return json.Marshal(value)
}

func nullableString(
	value string,
) any {
	trimmedValue := strings.TrimSpace(value)

	if trimmedValue == "" {
		return nil
	}

	return trimmedValue
}
