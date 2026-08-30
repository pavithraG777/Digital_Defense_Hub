package dfir

import (
	"testing"

	"github.com/google/uuid"
)

func TestFindRelatedIncidentsBySignalOverlap(t *testing.T) {
	service := NewService()
	orgID := uuid.New()

	incidentA, err := service.CreateIncident(orgID, "Initial file encryption", []string{"canary_access", "rapid_file_encryption", "shadow_copy_deletion"})
	if err != nil {
		t.Fatalf("CreateIncident A returned error: %v", err)
	}
	incidentB, err := service.CreateIncident(orgID, "Related encryption activity", []string{"canary_access", "rapid_file_encryption", "backup_deletion"})
	if err != nil {
		t.Fatalf("CreateIncident B returned error: %v", err)
	}
	incidentC, err := service.CreateIncident(orgID, "Unrelated suspicious login", []string{"failed_login", "privilege_escalation"})
	if err != nil {
		t.Fatalf("CreateIncident C returned error: %v", err)
	}

	related, err := service.FindRelatedIncidents(incidentA.ID)
	if err != nil {
		t.Fatalf("FindRelatedIncidents returned error: %v", err)
	}
	if len(related) == 0 {
		t.Fatal("expected at least one related incident")
	}

	foundB := false
	for _, item := range related {
		if item.IncidentID == incidentB.ID {
			foundB = true
			if item.SharedSignals < 1 {
				t.Fatalf("expected shared signals for incident B to be >= 1, got %d", item.SharedSignals)
			}
			break
		}
	}
	if !foundB {
		t.Fatal("expected incident B to be identified as related")
	}

	for _, item := range related {
		if item.IncidentID == incidentC.ID {
			t.Fatal("expected unrelated incident C not to appear in related incidents")
		}
	}
}
