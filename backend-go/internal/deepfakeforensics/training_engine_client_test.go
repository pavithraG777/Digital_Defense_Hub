package deepfakeforensics

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestTrainingEngineRequestMapsForensicSelectionControls(t *testing.T) {
	job := claimedTrainingJob{
		ID:                    uuid.New(),
		OrganizationID:        uuid.New(),
		DatasetVersionID:      uuid.New(),
		DatasetPath:           "/datasets/sample",
		ModelCode:             "face-context",
		TrainingConfiguration: []byte(`{"epochs":8,"batch_size":16,"learning_rate":0.0003,"deepfake_class_weight":1.25,"selection_metric":"f1","seed":20260823}`),
		SplitConfiguration:    []byte(`{"validation":15,"test":15}`),
	}

	request, err := trainingEngineRequest(job)
	if err != nil {
		t.Fatalf("unexpected request mapping error: %v", err)
	}
	if request.DeepfakeClassWeight != 1.25 || request.SelectionMetric != "f1" {
		t.Fatalf("unexpected forensic controls: weight=%v metric=%q", request.DeepfakeClassWeight, request.SelectionMetric)
	}
}

func TestVerifyTrainingArtifactMapsSharedMountAndChecksHash(t *testing.T) {
	backendRoot := t.TempDir()
	artifact := filepath.Join(backendRoot, "org", "job.pth")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("trained artifact")
	if err := os.WriteFile(artifact, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	resolved, err := VerifyTrainingArtifact("/models/trained/org/job.pth", "/models/trained", backendRoot, fmt.Sprintf("%x", digest))
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if resolved != artifact {
		t.Fatalf("expected %s, got %s", artifact, resolved)
	}
}

func TestVerifyTrainingArtifactAcceptsLocalWindowsStyleSharedRoot(t *testing.T) {
	backendRoot := t.TempDir()
	artifact := filepath.Join(backendRoot, "org", "job.pth")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("local trained artifact")
	if err := os.WriteFile(artifact, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	resolved, err := VerifyTrainingArtifact(artifact, backendRoot, backendRoot, fmt.Sprintf("%x", digest))
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if resolved != artifact {
		t.Fatalf("expected %s, got %s", artifact, resolved)
	}
}
