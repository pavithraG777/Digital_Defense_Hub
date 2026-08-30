package deepfakeforensics

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateModelArtifactExtension(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{name: "onnx supported", filename: "model.onnx", wantErr: false},
		{name: "pth supported", filename: "model.pth", wantErr: false},
		{name: "pt supported", filename: "model.pt", wantErr: false},
		{name: "unsupported extension", filename: "model.bin", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateModelArtifactExtension(tc.filename)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %s", tc.filename)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %s: %v", tc.filename, err)
			}
		})
	}
}

func TestResolveModelStoragePathRejectsTraversal(t *testing.T) {
	storageRoot := filepath.Join(t.TempDir(), "models")
	_, err := resolveModelStoragePath(storageRoot, "../unsafe-model.onnx")
	if err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Fatalf("expected outside-root error, got %v", err)
	}
}

func TestResolveModelStoragePathKeepsFileInsideRoot(t *testing.T) {
	storageRoot := filepath.Join(t.TempDir(), "models")
	resolvedPath, err := resolveModelStoragePath(storageRoot, "image_deepfake_v1.onnx")
	if err != nil {
		t.Fatalf("expected resolved path, got %v", err)
	}
	if !strings.HasPrefix(resolvedPath, storageRoot) {
		t.Fatalf("expected path inside storage root, got %s", resolvedPath)
	}
}

func TestInferModelIOForDocumentForensics(t *testing.T) {
	inputType, outputType := inferModelIO(JobTypeDocumentForensics)
	if inputType != "DOCUMENT" || outputType != "CLASSIFICATION" {
		t.Fatalf("expected DOCUMENT/CLASSIFICATION for %s, got %s/%s", JobTypeDocumentForensics, inputType, outputType)
	}
}

func TestInferModelIOForCrossModalVideoJobs(t *testing.T) {
	cases := []struct {
		jobType    string
		wantInput  string
		wantOutput string
	}{
		{jobType: JobTypeAudioVisualConsistency, wantInput: "VIDEO", wantOutput: "CONSISTENCY"},
		{jobType: JobTypeLipSyncConsistency, wantInput: "VIDEO", wantOutput: "CONSISTENCY"},
		{jobType: JobTypeMetadataIntegrity, wantInput: "VIDEO", wantOutput: "CONSISTENCY"},
	}

	for _, tc := range cases {
		inputType, outputType := inferModelIO(tc.jobType)
		if inputType != tc.wantInput || outputType != tc.wantOutput {
			t.Fatalf("expected %s/%s for %s, got %s/%s", tc.wantInput, tc.wantOutput, tc.jobType, inputType, outputType)
		}
	}
}

func TestSyntheticImageDetectorContract(t *testing.T) {
	inputType, outputType := inferModelIO(JobTypeSyntheticImage)
	if inputType != "IMAGE" || outputType != "CLASSIFICATION" {
		t.Fatalf("expected IMAGE/CLASSIFICATION, got %s/%s", inputType, outputType)
	}
	if !IsSupportedJobType(JobTypeSyntheticImage) {
		t.Fatal("expected synthetic image detector job type to be supported")
	}
	if !IsDeepfakeAssessmentJobType(JobTypeSyntheticImage) {
		t.Fatal("expected synthetic detector to use the shared authenticity assessment contract")
	}
	if IsDeepfakeJobType(JobTypeSyntheticImage) {
		t.Fatal("synthetic detector must remain distinct from face-manipulation deepfake jobs")
	}
}
