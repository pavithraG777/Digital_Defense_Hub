package deepfakeforensics

import (
	"strings"
	"testing"
)

func TestForensicsJobTypeForMediaSupportsDocument(t *testing.T) {
	jobType, ok := forensicsJobTypeForMedia(MediaTypeDocument)
	if !ok {
		t.Fatal("expected document forensics to be supported for DOCUMENT media type")
	}
	if jobType != JobTypeDocumentForensics {
		t.Fatalf("expected job type %s, got %s", JobTypeDocumentForensics, jobType)
	}
}

func TestJobTypesForAnalysisModesSupportsDocumentForensics(t *testing.T) {
	jobTypes, err := jobTypesForAnalysisModes(MediaTypeDocument, []string{AnalysisModeForensics})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jobTypes) != 1 {
		t.Fatalf("expected 1 job type, got %d", len(jobTypes))
	}
	if jobTypes[0] != JobTypeDocumentForensics {
		t.Fatalf("expected job type %s, got %s", JobTypeDocumentForensics, jobTypes[0])
	}
}

func TestJobTypesForAnalysisModesSupportsOCROnDocument(t *testing.T) {
	jobTypes, err := jobTypesForAnalysisModes(MediaTypeDocument, []string{AnalysisModeOCR})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jobTypes) != 1 {
		t.Fatalf("expected 1 job type, got %d", len(jobTypes))
	}
	if jobTypes[0] != JobTypeOCRExtraction {
		t.Fatalf("expected job type %s, got %s", JobTypeOCRExtraction, jobTypes[0])
	}
}

func TestJobTypesForAnalysisModesRejectsDeepfakeOnDocument(t *testing.T) {
	_, err := jobTypesForAnalysisModes(MediaTypeDocument, []string{AnalysisModeDeepfake})
	if err == nil {
		t.Fatal("expected deepfake analysis to be unsupported for DOCUMENT media type")
	}
	if !strings.Contains(err.Error(), "unsupported analysis mode") {
		t.Fatalf("expected unsupported analysis mode error, got %v", err)
	}
}

func TestJobTypesForAnalysisModesSupportsSyntheticImageDetection(t *testing.T) {
	jobTypes, err := jobTypesForAnalysisModes(MediaTypeImage, []string{AnalysisModeSynthetic})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jobTypes) != 1 || jobTypes[0] != JobTypeSyntheticImage {
		t.Fatalf("expected only %s, got %v", JobTypeSyntheticImage, jobTypes)
	}
}

func TestJobTypesForAnalysisModesRejectsSyntheticDetectionOnVideo(t *testing.T) {
	_, err := jobTypesForAnalysisModes(MediaTypeVideo, []string{AnalysisModeSynthetic})
	if err == nil {
		t.Fatal("expected synthetic image detection to reject VIDEO media")
	}
}
