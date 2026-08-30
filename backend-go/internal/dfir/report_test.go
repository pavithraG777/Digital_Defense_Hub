package dfir

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGenerateInvestigationReport(t *testing.T) {
	service := NewService()
	orgID := uuid.New()
	incident, err := service.CreateIncident(orgID, "Finance ransomware triage", []string{"canary_access", "rapid_file_encryption", "shadow_copy_deletion"})
	if err != nil {
		t.Fatalf("CreateIncident returned error: %v", err)
	}
	if _, err := service.AddEvidence(incident.ID, "file", "/tmp/finance/notes.xlsx", "hash-123"); err != nil {
		t.Fatalf("AddEvidence returned error: %v", err)
	}
	if _, err := service.AddTimelineEvent(incident.ID, "file_encryption", "endpoint-02", map[string]interface{}{"path": "/tmp/finance/notes.xlsx", "time": time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatalf("AddTimelineEvent returned error: %v", err)
	}

	report, err := service.GenerateInvestigationReport(incident.ID)
	if err != nil {
		t.Fatalf("GenerateInvestigationReport returned error: %v", err)
	}
	if report == nil || report.ID == uuid.Nil {
		t.Fatal("expected generated investigation report")
	}
	if len(report.JSONReport) == 0 {
		t.Fatal("expected JSON report payload to be generated")
	}
	if len(report.PDFReport) == 0 {
		t.Fatal("expected PDF report payload to be generated")
	}
	if report.Severity == "" {
		t.Fatal("expected report severity to be set")
	}
}
