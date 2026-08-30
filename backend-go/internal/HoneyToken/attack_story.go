package honeytoken

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// AttackStoryActivity is a non-sensitive representation of a threat event.
type AttackStoryActivity struct {
	OrganizationID uuid.UUID
	ThreatID       uuid.UUID
	FileEventID    uuid.UUID
	ThreatCode     string
	ThreatType     string
	Title          string
	Severity       string
	Classification string
	EventType      string
	DeviceName     string
	OccurredAt     time.Time
}

// AttackStoryPublisher persists a correlated event in the incident narrative.
type AttackStoryPublisher interface {
	RecordAttackStoryActivity(context.Context, AttackStoryActivity) error
}

func (w *ThreatWorker) publishAttackStoryActivity(
	ctx context.Context,
	threat *ThreatResponse,
	signal ThreatSignal,
) error {
	if w == nil || threat == nil || signal.FileEventID == uuid.Nil {
		return nil
	}

	w.mu.RLock()
	publisher := w.attackStoryPublisher
	w.mu.RUnlock()
	if publisher == nil {
		return nil
	}

	organizationID, err := parseSecurityNotificationUUID(threat.OrganizationID, "organization ID")
	if err != nil {
		return err
	}
	threatID, err := parseSecurityNotificationUUID(threat.ID, "threat ID")
	if err != nil {
		return err
	}

	deviceName := ""
	if threat.DeviceName != nil {
		deviceName = *threat.DeviceName
	}
	return publisher.RecordAttackStoryActivity(ctx, AttackStoryActivity{
		OrganizationID: organizationID,
		ThreatID:       threatID,
		FileEventID:    signal.FileEventID,
		ThreatCode:     threat.ThreatCode,
		ThreatType:     threat.ThreatType,
		Title:          threat.Title,
		Severity:       threat.Severity,
		Classification: threat.Classification,
		EventType:      signal.EventType,
		DeviceName:     deviceName,
		OccurredAt:     signal.OccurredAt,
	})
}
