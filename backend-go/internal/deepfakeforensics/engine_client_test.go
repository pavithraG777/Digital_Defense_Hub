package deepfakeforensics

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateSuccessfulEngineResponseForDocumentForensics(t *testing.T) {
	response := &MediaEngineResponse{
		RequestID:      uuid.New(),
		AnalysisJobID:  uuid.New(),
		OrganizationID: uuid.New(),
		Success:        true,
		Runtime:        "ONNX_RUNTIME",
		ForensicsAssessment: &EngineForensicsAssessment{
			MediaType:       MediaTypeDocument,
			ForensicResult:  ForensicResultManipulated,
			ConfidenceScore: 92.4,
			AnalysisSummary: "Document integrity check flagged manipulation",
			Findings:        []string{"embedded metadata mismatch"},
		},
		ProcessingDurationMS: 1234,
		ProcessedAt:          time.Now().UTC(),
	}

	err := validateSuccessfulEngineResponse(
		response,
		JobTypeDocumentForensics,
	)
	if err != nil {
		t.Fatalf("expected valid document forensics response, got %v", err)
	}
}

func TestValidateSuccessfulEngineResponseForDocumentOCR(t *testing.T) {
	response := &MediaEngineResponse{
		RequestID:      uuid.New(),
		AnalysisJobID:  uuid.New(),
		OrganizationID: uuid.New(),
		Success:        true,
		Runtime:        "TESSERACT",
		OCRAssessment: &EngineOCRAssessment{
			SourceMediaType:          MediaTypeDocument,
			ExtractionResult:         "TEXT_FOUND",
			OCREngine:                "TESSERACT",
			WordCount:                523,
			CharacterCount:           3200,
			DetectedLanguage:         ptrString("en"),
			ConfidenceScore:          ptrFloat64(87.5),
			RequiresManualCorrection: false,
		},
		ProcessingDurationMS: 456,
		ProcessedAt:          time.Now().UTC(),
	}

	err := validateSuccessfulEngineResponse(
		response,
		JobTypeOCRExtraction,
	)
	if err != nil {
		t.Fatalf("expected valid OCR response for document, got %v", err)
	}
}

func ptrString(value string) *string {
	return &value
}

func ptrFloat64(value float64) *float64 {
	return &value
}
