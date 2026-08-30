package dfir

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCreateIncidentAndEvidenceWorkflow(t *testing.T) {
	service := NewService()
	orgID := uuid.New()

	incident, err := service.CreateIncident(orgID, "Ransomware behavior on finance endpoint", []string{"canary_access", "rapid_file_encryption", "shadow_copy_deletion"})
	if err != nil {
		t.Fatalf("CreateIncident returned error: %v", err)
	}
	if incident == nil || incident.ID == uuid.Nil {
		t.Fatal("expected incident to be created")
	}
	if incident.Severity == "" {
		t.Fatal("expected incident severity to be set")
	}

	evidence, err := service.AddEvidence(incident.ID, "file_observation", "/tmp/finance/notes.xlsx", "sha256-abc123")
	if err != nil {
		t.Fatalf("AddEvidence returned error: %v", err)
	}
	if evidence == nil || evidence.ID == uuid.Nil {
		t.Fatal("expected evidence artifact to be created")
	}

	event, err := service.AddTimelineEvent(incident.ID, "suspicious_process_start", "endpoint-01", map[string]interface{}{"command": "powershell -enc ..."})
	if err != nil {
		t.Fatalf("AddTimelineEvent returned error: %v", err)
	}
	if event == nil || event.ID == uuid.Nil {
		t.Fatal("expected timeline event to be created")
	}
	if event.Timestamp.IsZero() {
		t.Fatal("expected timeline event timestamp to be set")
	}

	summary := service.IncidentSummary(incident.ID)
	if summary == nil {
		t.Fatal("expected incident summary for created incident")
	}
	if summary.EvidenceCount != 1 {
		t.Fatalf("expected 1 evidence item, got %d", summary.EvidenceCount)
	}
	if summary.TimelineCount != 1 {
		t.Fatalf("expected 1 timeline event, got %d", summary.TimelineCount)
	}
	if summary.LastUpdated.Before(time.Now().Add(-time.Minute)) {
		t.Fatal("expected incident summary timestamp to be recent")
	}
}

func TestListIncidentsAndEvidence(t *testing.T) {
	service := NewService()
	orgID := uuid.New()

	incident, err := service.CreateIncident(orgID, "Finance endpoint encryption", []string{"canary_access", "rapid_file_encryption"})
	if err != nil {
		t.Fatalf("CreateIncident returned error: %v", err)
	}
	if _, err := service.AddEvidence(incident.ID, "file_observation", "/tmp/case.xlsx", "sha256-123"); err != nil {
		t.Fatalf("AddEvidence returned error: %v", err)
	}
	if _, err := service.AddTimelineEvent(incident.ID, "file_access", "endpoint-01", map[string]interface{}{"path": "/tmp/case.xlsx"}); err != nil {
		t.Fatalf("AddTimelineEvent returned error: %v", err)
	}

	list, err := service.ListIncidents(orgID)
	if err != nil {
		t.Fatalf("ListIncidents returned error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(list))
	}
	if list[0].ID != incident.ID {
		t.Fatalf("expected incident id %s, got %s", incident.ID, list[0].ID)
	}

	evidence, err := service.ListEvidence(incident.ID)
	if err != nil {
		t.Fatalf("ListEvidence returned error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence artifact, got %d", len(evidence))
	}

	timeline, err := service.ListTimeline(incident.ID)
	if err != nil {
		t.Fatalf("ListTimeline returned error: %v", err)
	}
	if len(timeline) != 1 {
		t.Fatalf("expected 1 timeline event, got %d", len(timeline))
	}
}

func TestAssessRansomwareIndicators(t *testing.T) {
	service := NewService()

	response := service.AssessRansomwareIndicators(AssessmentRequest{
		Signals: []string{
			"canary_access",
			"rapid_file_encryption",
			"shadow_copy_deletion",
		},
		EvidenceCount: 4,
	})

	if response.Score <= 0 {
		t.Fatalf("expected a positive score, got %v", response.Score)
	}

	if response.Severity != "high" && response.Severity != "critical" {
		t.Fatalf("expected a high or critical severity, got %s", response.Severity)
	}

	if response.Confidence <= 0.5 {
		t.Fatalf("expected confidence above 0.5, got %v", response.Confidence)
	}
}

func TestAssessRansomwareIndicatorsUsesHybridMLScoring(t *testing.T) {
	service := NewService()

	response := service.AssessRansomwareIndicators(AssessmentRequest{
		Signals: []string{
			"suspicious_powershell",
			"unusual_network_transfer",
		},
		EvidenceCount: 2,
	})

	if response.Mode != "hybrid" {
		t.Fatalf("expected hybrid mode, got %s", response.Mode)
	}

	if response.MLScore <= 0 {
		t.Fatalf("expected a positive ML score, got %v", response.MLScore)
	}

	if response.ModelVersion == "" {
		t.Fatalf("expected a model version to be present")
	}
}
