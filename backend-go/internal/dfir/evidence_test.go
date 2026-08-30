package dfir

import (
	"testing"

	"github.com/google/uuid"
)

func TestHashEvidenceAndValidation(t *testing.T) {
	payload := []byte("forensic sample payload")
	hash := HashEvidence(payload)
	if hash == "" {
		t.Fatal("expected a non-empty SHA256 hash")
	}
	if !ValidateEvidenceHash(hash, payload) {
		t.Fatal("expected hash validation to succeed for matching payload")
	}
	if ValidateEvidenceHash(hash, []byte("different payload")) {
		t.Fatal("expected hash validation to fail for different payload")
	}
}

func TestPreserveEvidenceAndChainOfCustody(t *testing.T) {
	service := NewService()
	incident, err := service.CreateIncident(uuid.New(), "evidence custody workflow", []string{"canary_access"})
	if err != nil {
		t.Fatalf("CreateIncident returned error: %v", err)
	}

	artifact, err := service.PreserveEvidence(incident.ID, "file", "/tmp/finance/notes.xlsx", []byte("encrypted payload"), "analyst-01")
	if err != nil {
		t.Fatalf("PreserveEvidence returned error: %v", err)
	}
	if artifact == nil || artifact.ID == uuid.Nil {
		t.Fatal("expected preserved evidence artifact")
	}
	if artifact.Hash == "" {
		t.Fatal("expected preserved artifact hash to be populated")
	}

	if err := service.AddChainOfCustody(incident.ID, artifact.ID, "analyst-01", "collected", "file sealed for investigation"); err != nil {
		t.Fatalf("AddChainOfCustody returned error: %v", err)
	}
	if _, err := service.GetChainOfCustody(artifact.ID); err != nil {
		t.Fatalf("GetChainOfCustody returned error: %v", err)
	}
}
