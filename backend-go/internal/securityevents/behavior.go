package securityevents

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"math"
	"sort"
	"strings"
	"time"
)

type metricPayload struct {
	Metric string  `json:"metric"`
	Value  float64 `json:"value"`
}

func anomalyScore(value, mean, stddev float64) (float64, float64) {
	deviation := math.Abs(value - mean)
	if stddev < 0.0001 {
		if deviation == 0 {
			return 0, 0
		}
		return 1, deviation
	}
	z := deviation / stddev
	score := 1 - math.Exp(-z/3)
	if score > 1 {
		score = 1
	}
	return math.Round(score*10000) / 10000, math.Round(z*10000) / 10000
}
func processIntelligence(ctx context.Context, db *pgxpool.Pool, org, event uuid.UUID) error {
	var eventType string
	var observed time.Time
	var payload []byte
	e := db.QueryRow(ctx, `SELECT event_type,observed_at,payload FROM normalized_security_events WHERE organization_id=$1 AND id=$2`, org, event).Scan(&eventType, &observed, &payload)
	if e != nil {
		return e
	}
	var metric metricPayload
	_ = json.Unmarshal(payload, &metric)
	if strings.TrimSpace(metric.Metric) != "" {
		if e = updateBaseline(ctx, db, org, event, metric, observed); e != nil {
			return e
		}
	}
	risk, rule, explanation := behaviorRisk(eventType, payload)
	if risk < .6 {
		return nil
	}
	severity := "MEDIUM"
	if risk >= .9 {
		severity = "CRITICAL"
	} else if risk >= .75 {
		severity = "HIGH"
	}
	finding := uuid.New()
	_, e = db.Exec(ctx, `INSERT INTO security_behavior_detections(id,organization_id,event_id,rule_code,rule_version,severity,risk_score,explanation,observed_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8) ON CONFLICT(organization_id,event_id,rule_code,rule_version) DO NOTHING`, finding, org, event, rule, severity, risk, explanation, observed)
	if e != nil {
		return e
	}
	return upsertAttackStory(ctx, db, org, event, finding, eventType, severity, risk, explanation, observed)
}
func behaviorRisk(kind string, payload []byte) (float64, string, []string) {
	k := strings.ToUpper(kind)
	rules := []struct {
		tokens []string
		score  float64
		code   string
	}{{[]string{"PASSWORD_SPRAY", "CREDENTIAL_STUFFING", "TOKEN_REPLAY"}, .9, "CREDENTIAL_ABUSE_SEQUENCE"}, {[]string{"PRIVILEGE_ESCALATION", "ADMIN_ROLE_ASSIGNED", "SUDO_EXECUTION"}, .85, "PRIVILEGE_ELEVATION"}, {[]string{"REMOTE_EXECUTION", "ADMIN_SHARE_ACCESS", "LATERAL_MOVEMENT"}, .85, "LATERAL_MOVEMENT"}, {[]string{"POWERSHELL_ENCODED", "SCRIPT_OBFUSCATION"}, .8, "SUSPICIOUS_SCRIPT_EXECUTION"}, {[]string{"HONEYTOKEN_ACCESS", "FILE_ENCRYPTION"}, .95, "DECEPTION_OR_IMPACT"}}
	for _, r := range rules {
		for _, token := range r.tokens {
			if strings.Contains(k, token) {
				return r.score, r.code, []string{fmt.Sprintf("event type %s matched behavior token %s", kind, token)}
			}
		}
	}
	return 0, "", nil
}
func updateBaseline(ctx context.Context, db *pgxpool.Pool, org, event uuid.UUID, m metricPayload, observed time.Time) error {
	var count int
	var mean, m2 float64
	e := db.QueryRow(ctx, `SELECT sample_count,mean,m2 FROM security_baseline_models WHERE organization_id=$1 AND metric=$2 AND model_version=1`, org, m.Metric).Scan(&count, &mean, &m2)
	if e != nil {
		count = 0
		mean = 0
		m2 = 0
	}
	oldMean := mean
	stddev := 0.0
	if count > 1 {
		stddev = math.Sqrt(m2 / float64(count-1))
	}
	score, z := anomalyScore(m.Value, oldMean, stddev)
	count++
	delta := m.Value - mean
	mean += delta / float64(count)
	m2 += delta * (m.Value - mean)
	_, e = db.Exec(ctx, `INSERT INTO security_baseline_models(id,organization_id,metric,model_version,sample_count,mean,m2,last_observed_at) VALUES($1,$2,$3,1,$4,$5,$6,$7) ON CONFLICT(organization_id,metric,model_version) DO UPDATE SET sample_count=$4,mean=$5,m2=$6,last_observed_at=GREATEST(security_baseline_models.last_observed_at,$7),updated_at=NOW()`, uuid.New(), org, m.Metric, count, mean, m2, observed)
	if e != nil {
		return e
	}
	if count >= 10 && score >= .7 {
		_, e = db.Exec(ctx, `INSERT INTO security_baseline_anomalies(id,organization_id,event_id,metric,model_version,observed_value,baseline_mean,baseline_stddev,z_score,anomaly_score,explanation,observed_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(organization_id,event_id,metric,model_version) DO NOTHING`, uuid.New(), org, event, m.Metric, m.Value, oldMean, stddev, z, score, []string{fmt.Sprintf("value %.4f deviates from learned mean %.4f", m.Value, oldMean)}, observed)
	}
	return e
}
func upsertAttackStory(ctx context.Context, db *pgxpool.Pool, org, event, finding uuid.UUID, eventType, severity string, risk float64, explanation []string, observed time.Time) error {
	var incident *uuid.UUID
	_ = db.QueryRow(ctx, `SELECT se.id FROM security_entities se JOIN security_event_entities ee ON ee.entity_id=se.id AND ee.organization_id=se.organization_id WHERE ee.organization_id=$1 AND ee.event_id=$2 AND se.entity_type='INCIDENT' LIMIT 1`, org, event).Scan(&incident)
	storyKey := "tenant-active"
	if incident != nil {
		storyKey = incident.String()
	}
	var story uuid.UUID
	var version int
	e := db.QueryRow(ctx, `SELECT id,current_version FROM security_attack_stories WHERE organization_id=$1 AND story_key=$2`, org, storyKey).Scan(&story, &version)
	if e != nil {
		story = uuid.New()
		version = 0
		_, e = db.Exec(ctx, `INSERT INTO security_attack_stories(id,organization_id,story_key,title,current_version,status) VALUES($1,$2,$3,$4,0,'ACTIVE')`, story, org, storyKey, "Automatically correlated attack story")
		if e != nil {
			return e
		}
	}
	version++
	rows, e := db.Query(ctx, `SELECT event_type,observed_at,id FROM normalized_security_events WHERE organization_id=$1 AND id IN(SELECT DISTINCT unnest(event_ids) FROM security_correlation_findings WHERE organization_id=$1 AND $2=ANY(event_ids) UNION SELECT $2) ORDER BY observed_at,id`, org, event)
	if e != nil {
		return e
	}
	timeline := []map[string]any{}
	for rows.Next() {
		var kind string
		var at time.Time
		var id uuid.UUID
		if e = rows.Scan(&kind, &at, &id); e != nil {
			rows.Close()
			return e
		}
		timeline = append(timeline, map[string]any{"event_id": id, "event_type": kind, "timestamp": at})
	}
	rows.Close()
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i]["timestamp"].(time.Time).Before(timeline[j]["timestamp"].(time.Time))
	})
	_, e = db.Exec(ctx, `INSERT INTO security_attack_story_versions(id,story_id,organization_id,version,timeline,trigger_detection_id,summary) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), story, org, version, timeline, finding, map[string]any{"latest_event_type": eventType, "severity": severity, "risk_score": risk, "explanation": explanation})
	if e != nil {
		return e
	}
	_, e = db.Exec(ctx, `UPDATE security_attack_stories SET current_version=$3,updated_at=NOW() WHERE organization_id=$1 AND id=$2`, org, story, version)
	return e
}
