package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
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

// ListTimeline keeps filtering and pagination in PostgreSQL.  The UNION is
// intentionally normalized here instead of leaving every caller to merge
// partially-filtered feeds in memory.
func (r *Repository) ListTimeline(ctx context.Context, organizationID uuid.UUID, filter TimelineFilter) (*TimelinePage, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("audit repository is unavailable")
	}
	if filter.Limit < 1 {
		filter.Limit = 50
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	const events = `
WITH timeline AS (
 SELECT 'ADMIN_AUDIT'::text source_type, id::text id, id::text event_code, action_name event_type, module_name event_source, COALESCE(NULLIF(entity_type,''),description,'Administrative event') resource, COALESCE(user_id::text,'') actor, COALESCE(device_name,'') device_name, risk_level severity, result_status status, occurred_at
 FROM audit_logs WHERE organization_id=$1
 UNION ALL
 SELECT source_type, id::text, event_code, event_type, event_source, file_name, COALESCE(system_username,application_user_id::text,''), COALESCE(device_name,''), severity, status, occurred_at
 FROM file_events WHERE organization_id=$1
 UNION ALL
 SELECT 'THREAT'::text, id::text, threat_code, threat_type, threat_category, title, COALESCE(assigned_to::text,created_by::text,''), COALESCE(source_device_name,''), severity, status, last_detected_at
 FROM threats WHERE organization_id=$1 AND deleted_at IS NULL
 UNION ALL
 SELECT 'INCIDENT'::text, it.id::text, i.incident_number, it.event_type, 'INCIDENT_TIMELINE', it.title, COALESCE(it.actor_user_id::text,''), '', COALESCE(i.severity,'MEDIUM'), COALESCE(it.new_status,i.status), it.occurred_at
 FROM incident_timeline it JOIN incidents i ON i.id=it.incident_id AND i.organization_id=it.organization_id WHERE it.organization_id=$1
 UNION ALL
 SELECT 'FORENSIC_REVIEW'::text, r.id::text, j.job_number, r.decision, 'MEDIA_FORENSICS', COALESCE(a.original_file_name,j.job_number), r.reviewer_user_id::text, '', CASE WHEN r.decision='ESCALATED' THEN 'HIGH' ELSE 'MEDIUM' END, 'REVIEWED', r.reviewed_at
 FROM media_forensic_reviews r JOIN ai_analysis_jobs j ON j.id=r.analysis_job_id AND j.organization_id=r.organization_id LEFT JOIN media_analysis_assets a ON a.id=j.media_asset_id AND a.organization_id=j.organization_id WHERE r.organization_id=$1
 UNION ALL
 SELECT 'FORENSIC_ANNOTATION'::text, n.id::text, j.job_number, n.annotation_type, 'MEDIA_FORENSICS', COALESCE(a.original_file_name,j.job_number), n.created_by::text, '', CASE WHEN n.annotation_type='ESCALATION' THEN 'HIGH' ELSE 'LOW' END, 'ANNOTATED', n.created_at
 FROM media_forensic_annotations n JOIN ai_analysis_jobs j ON j.id=n.analysis_job_id AND j.organization_id=n.organization_id LEFT JOIN media_analysis_assets a ON a.id=j.media_asset_id AND a.organization_id=j.organization_id WHERE n.organization_id=$1
), filtered AS (
 SELECT * FROM timeline WHERE
 ($2='' OR source_type=$2) AND ($3='' OR severity=$3) AND
 ($4='' OR concat_ws(' ',source_type,event_code,event_type,event_source,resource,actor,device_name,status) ILIKE '%' || $4 || '%') AND
 ($5::timestamptz IS NULL OR occurred_at >= $5) AND ($6::timestamptz IS NULL OR occurred_at <= $6) AND
 (NOT $7::boolean OR severity IN ('HIGH','CRITICAL'))
)
SELECT id, source_type, event_code, event_type, event_source, resource, actor, device_name, severity, status, occurred_at, count(*) OVER() total FROM filtered ORDER BY occurred_at DESC, id DESC LIMIT $8 OFFSET $9`
	rows, err := r.db.Query(ctx, events, organizationID, strings.ToUpper(strings.TrimSpace(filter.SourceType)), strings.ToUpper(strings.TrimSpace(filter.RiskLevel)), strings.TrimSpace(filter.Search), filter.From, filter.To, filter.Suspicious, filter.Limit, filter.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &TimelinePage{Items: make([]TimelineEvent, 0)}
	for rows.Next() {
		var item TimelineEvent
		var total int
		if err := rows.Scan(&item.ID, &item.SourceType, &item.EventCode, &item.EventType, &item.EventSource, &item.Resource, &item.Actor, &item.DeviceName, &item.Severity, &item.Status, &item.OccurredAt, &total); err != nil {
			return nil, err
		}
		page.Items = append(page.Items, item)
		page.Total = total
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return page, nil
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
