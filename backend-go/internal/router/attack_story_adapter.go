package router

import (
	"context"
	"errors"

	honeytoken "github.com/pavithraG777/cyber-security-platform/backend/internal/HoneyToken"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/attackstory"
)

type attackStoryPublisher struct {
	repository *attackstory.Repository
}

func newAttackStoryPublisher(repository *attackstory.Repository) (honeytoken.AttackStoryPublisher, error) {
	if repository == nil {
		return nil, errors.New("attack story repository is required")
	}
	return &attackStoryPublisher{repository: repository}, nil
}

func (publisher *attackStoryPublisher) RecordAttackStoryActivity(ctx context.Context, activity honeytoken.AttackStoryActivity) error {
	if publisher == nil || publisher.repository == nil {
		return errors.New("attack story publisher is unavailable")
	}
	return publisher.repository.RecordThreatActivity(ctx, activity.OrganizationID, activity.ThreatID, activity.FileEventID, "Automated Attack Story: "+activity.Title, map[string]interface{}{
		"event_type":      activity.EventType,
		"threat_code":     activity.ThreatCode,
		"threat_type":     activity.ThreatType,
		"severity":        activity.Severity,
		"classification":  activity.Classification,
		"device_name":     activity.DeviceName,
		"mitre_technique": attackStoryTechnique(activity.ThreatType),
	}, activity.OccurredAt)
}

func attackStoryTechnique(threatType string) string {
	switch threatType {
	case honeytoken.ThreatTypeCanaryTriggered, honeytoken.ThreatTypeFileTampering:
		return "T1565"
	case honeytoken.ThreatTypeMassFileRename:
		return "T1486"
	case honeytoken.ThreatTypeMassFileDeletion:
		return "T1070.004"
	case honeytoken.ThreatTypeRansomwareActivity:
		return "T1486"
	default:
		return ""
	}
}
