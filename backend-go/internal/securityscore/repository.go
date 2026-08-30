package securityscore

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type signalRepository interface {
	listOrganizationSignals(context.Context, *uuid.UUID) ([]rawOrganizationSignals, error)
	threatInventory(context.Context, uuid.UUID) (ThreatInventory, error)
	threatTrend(context.Context, uuid.UUID) ([]ThreatTrendPoint, error)
	topThreats(context.Context, uuid.UUID, int) ([]SafeThreatRecord, error)
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) listOrganizationSignals(ctx context.Context, organizationID *uuid.UUID) ([]rawOrganizationSignals, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("security score repository is unavailable")
	}

	query := `
		WITH threat_stats AS (
			SELECT organization_id,
				COUNT(*) AS total_threats,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','ARCHIVED','FALSE_POSITIVE')) AS open_threats,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','ARCHIVED','FALSE_POSITIVE') AND severity='CRITICAL') AS open_critical,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','ARCHIVED','FALSE_POSITIVE') AND severity='HIGH') AS open_high,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','ARCHIVED','FALSE_POSITIVE') AND severity='MEDIUM') AS open_medium,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','ARCHIVED','FALSE_POSITIVE') AND severity='LOW') AS open_low,
				COALESCE(AVG(threat_score) FILTER (WHERE status NOT IN ('RESOLVED','ARCHIVED','FALSE_POSITIVE')),0)::double precision AS avg_score,
				COALESCE(MAX(threat_score) FILTER (WHERE status NOT IN ('RESOLVED','ARCHIVED','FALSE_POSITIVE')),0)::double precision AS max_score,
				MAX(last_detected_at) AS last_signal
			FROM threats
			WHERE deleted_at IS NULL
			GROUP BY organization_id
		), incident_stats AS (
			SELECT organization_id,
				COUNT(*) AS total_incidents,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','CLOSED','CANCELLED')) AS open_incidents,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','CLOSED','CANCELLED') AND severity='CRITICAL') AS open_critical,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','CLOSED','CANCELLED') AND severity='HIGH') AS open_high,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','CLOSED','CANCELLED') AND severity='MEDIUM') AS open_medium,
				COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','CLOSED','CANCELLED') AND severity='LOW') AS open_low,
				MAX(detected_at) AS last_signal
			FROM incidents
			WHERE deleted_at IS NULL
			GROUP BY organization_id
		), behavior_stats AS (
			SELECT organization_id,
				COUNT(*) AS detection_count,
				COALESCE(AVG(risk_score),0)::double precision AS avg_score,
				COALESCE(MAX(risk_score),0)::double precision AS max_score,
				MAX(observed_at) AS last_signal
			FROM security_behavior_detections
			WHERE observed_at >= NOW() - INTERVAL '30 days'
			GROUP BY organization_id
		)
		SELECT o.id, o.organization_code, COALESCE(NULLIF(o.display_name,''),o.legal_name), o.status,
			COALESCE(t.total_threats,0), COALESCE(t.open_threats,0), COALESCE(t.open_critical,0), COALESCE(t.open_high,0), COALESCE(t.open_medium,0), COALESCE(t.open_low,0), COALESCE(t.avg_score,0), COALESCE(t.max_score,0), t.last_signal,
			COALESCE(i.total_incidents,0), COALESCE(i.open_incidents,0), COALESCE(i.open_critical,0), COALESCE(i.open_high,0), COALESCE(i.open_medium,0), COALESCE(i.open_low,0), i.last_signal,
			COALESCE(b.detection_count,0), COALESCE(b.avg_score,0), COALESCE(b.max_score,0), b.last_signal
		FROM organizations o
		LEFT JOIN threat_stats t ON t.organization_id=o.id
		LEFT JOIN incident_stats i ON i.organization_id=o.id
		LEFT JOIN behavior_stats b ON b.organization_id=o.id
		WHERE o.deleted_at IS NULL
		  AND ($1::uuid IS NULL OR o.id=$1)
		ORDER BY o.organization_code;
	`

	var tenantFilter any
	if organizationID != nil {
		tenantFilter = *organizationID
	}
	rows, err := r.db.Query(ctx, query, tenantFilter)
	if err != nil {
		return nil, fmt.Errorf("query organization security signals: %w", err)
	}
	defer rows.Close()

	results := make([]rawOrganizationSignals, 0)
	for rows.Next() {
		var item rawOrganizationSignals
		var scannedOrganizationID uuid.UUID
		if err := rows.Scan(
			&scannedOrganizationID, &item.Organization.Code, &item.Organization.Name, &item.Organization.Status,
			&item.TotalThreats, &item.OpenThreats, &item.OpenCriticalThreats, &item.OpenHighThreats, &item.OpenMediumThreats, &item.OpenLowThreats, &item.AverageThreatScore, &item.MaximumThreatScore, &item.LastThreatAt,
			&item.TotalIncidents, &item.OpenIncidents, &item.OpenCriticalIncidents, &item.OpenHighIncidents, &item.OpenMediumIncidents, &item.OpenLowIncidents, &item.LastIncidentAt,
			&item.BehaviorDetections, &item.AverageBehaviorScore, &item.MaximumBehaviorScore, &item.LastBehaviorAt,
		); err != nil {
			return nil, fmt.Errorf("scan organization security signals: %w", err)
		}
		item.Organization.ID = scannedOrganizationID.String()
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate organization security signals: %w", err)
	}
	return results, nil
}

func (r *Repository) threatInventory(ctx context.Context, organizationID uuid.UUID) (ThreatInventory, error) {
	var inventory ThreatInventory
	const totalsQuery = `
		SELECT COUNT(*),
			COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','ARCHIVED','FALSE_POSITIVE')),
			COUNT(*) FILTER (WHERE status IN ('RESOLVED','ARCHIVED')),
			COUNT(*) FILTER (WHERE status='FALSE_POSITIVE'),
			COALESCE(SUM(occurrence_count),0), COALESCE(SUM(affected_file_count),0), COALESCE(SUM(affected_device_count),0)
		FROM threats WHERE organization_id=$1 AND deleted_at IS NULL;
	`
	if err := r.db.QueryRow(ctx, totalsQuery, organizationID).Scan(
		&inventory.Total, &inventory.Open, &inventory.Resolved, &inventory.FalsePositive,
		&inventory.TotalOccurrences, &inventory.AffectedFileCount, &inventory.AffectedDeviceCount,
	); err != nil {
		return inventory, fmt.Errorf("query threat inventory totals: %w", err)
	}

	var err error
	if inventory.Severity, err = r.distribution(ctx, organizationID, "severity"); err != nil {
		return inventory, err
	}
	if inventory.Status, err = r.distribution(ctx, organizationID, "status"); err != nil {
		return inventory, err
	}
	if inventory.Category, err = r.distribution(ctx, organizationID, "threat_category"); err != nil {
		return inventory, err
	}
	if inventory.DetectionMethod, err = r.distribution(ctx, organizationID, "detection_method"); err != nil {
		return inventory, err
	}
	return inventory, nil
}

func (r *Repository) distribution(ctx context.Context, organizationID uuid.UUID, column string) ([]DistributionItem, error) {
	allowed := map[string]bool{"severity": true, "status": true, "threat_category": true, "detection_method": true}
	if !allowed[column] {
		return nil, fmt.Errorf("unsupported threat distribution")
	}
	query := fmt.Sprintf(`SELECT %s, COUNT(*) FROM threats WHERE organization_id=$1 AND deleted_at IS NULL GROUP BY %s ORDER BY COUNT(*) DESC, %s`, column, column, column)
	rows, err := r.db.Query(ctx, query, organizationID)
	if err != nil {
		return nil, fmt.Errorf("query threat %s distribution: %w", column, err)
	}
	defer rows.Close()
	items := make([]DistributionItem, 0)
	for rows.Next() {
		var item DistributionItem
		if err := rows.Scan(&item.Value, &item.Count); err != nil {
			return nil, fmt.Errorf("scan threat %s distribution: %w", column, err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *Repository) threatTrend(ctx context.Context, organizationID uuid.UUID) ([]ThreatTrendPoint, error) {
	const query = `
		WITH days AS (SELECT generate_series(CURRENT_DATE-29,CURRENT_DATE,INTERVAL '1 day')::date AS day),
		daily AS (
			SELECT last_detected_at::date AS day, COUNT(*) AS detected,
				AVG(threat_score)::double precision AS average_score, MAX(threat_score)::double precision AS maximum_score
			FROM threats WHERE organization_id=$1 AND deleted_at IS NULL AND last_detected_at >= CURRENT_DATE-29
			GROUP BY last_detected_at::date
		)
		SELECT TO_CHAR(days.day,'YYYY-MM-DD'), COALESCE(daily.detected,0), COALESCE(daily.average_score,0), COALESCE(daily.maximum_score,0)
		FROM days LEFT JOIN daily USING(day) ORDER BY days.day;
	`
	rows, err := r.db.Query(ctx, query, organizationID)
	if err != nil {
		return nil, fmt.Errorf("query threat trend: %w", err)
	}
	defer rows.Close()
	items := make([]ThreatTrendPoint, 0, behaviorWindowDays)
	for rows.Next() {
		var item ThreatTrendPoint
		if err := rows.Scan(&item.Date, &item.Detected, &item.AverageScore, &item.MaximumScore); err != nil {
			return nil, fmt.Errorf("scan threat trend: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *Repository) topThreats(ctx context.Context, organizationID uuid.UUID, limit int) ([]SafeThreatRecord, error) {
	const query = `
		SELECT id, threat_code, title, threat_type, threat_category, detection_method, severity,
			threat_score, confidence_score::double precision, classification, status, occurrence_count,
			affected_file_count, first_detected_at, last_detected_at
		FROM threats WHERE organization_id=$1 AND deleted_at IS NULL
		ORDER BY threat_score DESC, last_detected_at DESC LIMIT $2;
	`
	rows, err := r.db.Query(ctx, query, organizationID, limit)
	if err != nil {
		return nil, fmt.Errorf("query top threats: %w", err)
	}
	defer rows.Close()
	items := make([]SafeThreatRecord, 0)
	for rows.Next() {
		var item SafeThreatRecord
		var scannedThreatID uuid.UUID
		if err := rows.Scan(&scannedThreatID, &item.Code, &item.Title, &item.Type, &item.Category, &item.DetectionMethod,
			&item.Severity, &item.Score, &item.Confidence, &item.Classification, &item.Status,
			&item.OccurrenceCount, &item.AffectedFileCount, &item.FirstDetectedAt, &item.LastDetectedAt); err != nil {
			return nil, fmt.Errorf("scan top threat: %w", err)
		}
		item.ID = scannedThreatID.String()
		items = append(items, item)
	}
	return items, rows.Err()
}
