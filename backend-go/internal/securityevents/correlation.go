package securityevents

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CorrelationRule struct {
	Code               string        `json:"code"`
	Version            int           `json:"version"`
	Name               string        `json:"name"`
	Window             time.Duration `json:"-"`
	MinimumEvents      int           `json:"minimum_events"`
	MinimumEntityTypes int           `json:"minimum_entity_types"`
	Severity           string        `json:"severity"`
}

var defaultRule = CorrelationRule{"MULTI_ENTITY_ACTIVITY", 1, "Multi-entity activity within event-time window", 30 * time.Minute, 2, 2, "HIGH"}

func correlationConfidence(events, types int, span, window time.Duration) float64 {
	density := 1.0
	if window > 0 {
		density = 1 - math.Min(1, float64(span)/float64(window))
	}
	score := .35 + math.Min(.3, float64(events-1)*.1) + math.Min(.2, float64(types)*.05) + density*.15
	if score > 1 {
		score = 1
	}
	return math.Round(score*10000) / 10000
}
func EnsureDefaultRule(ctx context.Context, db *pgxpool.Pool) error {
	_, e := db.Exec(ctx, `INSERT INTO security_correlation_rules(id,rule_code,version,name,window_seconds,minimum_events,minimum_entity_types,severity,definition,is_active) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,true) ON CONFLICT(rule_code,version) DO NOTHING`, uuid.New(), defaultRule.Code, defaultRule.Version, defaultRule.Name, int(defaultRule.Window.Seconds()), defaultRule.MinimumEvents, defaultRule.MinimumEntityTypes, defaultRule.Severity, map[string]any{"strategy": "shared_entity_time_window"})
	return e
}
func correlateEvent(ctx context.Context, db *pgxpool.Pool, org, eventID uuid.UUID) error {
	var observed time.Time
	e := db.QueryRow(ctx, `SELECT observed_at FROM normalized_security_events WHERE organization_id=$1 AND id=$2`, org, eventID).Scan(&observed)
	if e != nil {
		return e
	}
	rows, e := db.Query(ctx, `SELECT DISTINCT other.id,other.observed_at,ee.entity_id,se.entity_type FROM security_event_entities current JOIN security_event_entities ee ON ee.organization_id=current.organization_id AND ee.entity_id=current.entity_id JOIN normalized_security_events other ON other.organization_id=ee.organization_id AND other.id=ee.event_id JOIN security_entities se ON se.organization_id=ee.organization_id AND se.id=ee.entity_id WHERE current.organization_id=$1 AND current.event_id=$2 AND other.id<>$2 AND other.observed_at BETWEEN $3 AND $4`, org, eventID, observed.Add(-defaultRule.Window), observed.Add(defaultRule.Window))
	if e != nil {
		return e
	}
	defer rows.Close()
	events := map[uuid.UUID]time.Time{eventID: observed}
	entities := map[uuid.UUID]string{}
	for rows.Next() {
		var eid, entity uuid.UUID
		var at time.Time
		var kind string
		if e = rows.Scan(&eid, &at, &entity, &kind); e != nil {
			return e
		}
		events[eid] = at
		entities[entity] = kind
	}
	if len(events) < 2 {
		return rows.Err()
	}
	types := map[string]bool{}
	for _, kind := range entities {
		types[kind] = true
	}
	if len(types) < 2 {
		return nil
	}
	eventIDs := make([]uuid.UUID, 0, len(events))
	entityIDs := make([]uuid.UUID, 0, len(entities))
	first, last := observed, observed
	for id, at := range events {
		eventIDs = append(eventIDs, id)
		if at.Before(first) {
			first = at
		}
		if at.After(last) {
			last = at
		}
	}
	for id := range entities {
		entityIDs = append(entityIDs, id)
	}
	sort.Slice(eventIDs, func(i, j int) bool { return eventIDs[i].String() < eventIDs[j].String() })
	sort.Slice(entityIDs, func(i, j int) bool { return entityIDs[i].String() < entityIDs[j].String() })
	raw, _ := json.Marshal(struct {
		Rule             string
		Events, Entities []uuid.UUID
	}{defaultRule.Code, eventIDs, entityIDs})
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(raw))
	explanation := []string{fmt.Sprintf("%d events share %d entities", len(events), len(entities)), fmt.Sprintf("%d entity types linked within %s", len(types), defaultRule.Window)}
	_, e = db.Exec(ctx, `INSERT INTO security_correlation_findings(id,organization_id,rule_code,rule_version,severity,confidence,explanation,event_ids,entity_ids,first_observed_at,last_observed_at,fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(organization_id,fingerprint) DO UPDATE SET last_observed_at=GREATEST(security_correlation_findings.last_observed_at,EXCLUDED.last_observed_at),updated_at=NOW()`, uuid.New(), org, defaultRule.Code, defaultRule.Version, defaultRule.Severity, correlationConfidence(len(events), len(types), last.Sub(first), defaultRule.Window), explanation, eventIDs, entityIDs, first, last, fingerprint)
	return e
}
