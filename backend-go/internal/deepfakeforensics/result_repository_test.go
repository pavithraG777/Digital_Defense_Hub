package deepfakeforensics

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateAnalysisResultPersistenceDocumentForensics(t *testing.T) {
	organizationID := uuid.New()
	jobID := uuid.New()
	assetID := uuid.New()
	modelID := uuid.New()
	modelVersionID := uuid.New()

	source := AnalysisSource{
		Asset: MediaAnalysisAsset{
			ID:             assetID,
			OrganizationID: organizationID,
			MediaType:      MediaTypeDocument,
		},
		Model: AnalysisModelReference{
			ModelID:        modelID,
			ModelVersionID: modelVersionID,
			ModelCode:      "DOC_FORNS",
			ModelName:      "doc-forensics-model",
			ModelType:      JobTypeDocumentForensics,
			ModelStatus:    analysisModelStatusActive,
			VersionStatus:  analysisModelVersionStatusActive,
			IsDefault:      true,
			ModelFilePath:  "/tmp/model.onnx",
			ModelFileHash:  "abc123",
		},
		Job: AIAnalysisJob{
			ID:               jobID,
			OrganizationID:   organizationID,
			MediaAssetID:     &assetID,
			AIModelID:        modelID,
			AIModelVersionID: modelVersionID,
			JobType:          JobTypeDocumentForensics,
			Priority:         JobPriorityNormal,
			Status:           JobStatusProcessing,
		},
	}

	resultText := "MANIPULATED"
	bundle := &AnalysisResultBundle{
		Forensics: &MediaForensicsResult{
			ID:              uuid.New(),
			AnalysisJobID:   jobID,
			OrganizationID:  organizationID,
			MediaAssetID:    &assetID,
			MediaType:       MediaTypeDocument,
			ForensicResult:  ForensicResultManipulated,
			ConfidenceScore: ptrFloat64(82.3),
			AnalysisSummary: ptrString("forensic document integrity check"),
			Findings:        []string{"embedded metadata mismatch"},
			CreatedAt:       time.Now().UTC(),
		},
		EvidenceAnalysis: EvidenceAnalysis{
			ID:             uuid.New(),
			OrganizationID: organizationID,
			AnalysisJobID:  &jobID,
			MediaAssetID:   &assetID,
			AnalysisType:   JobTypeDocumentForensics,
			AnalysisMethod: AnalysisMethodAIBased,
			AnalysisStatus: AnalysisStatusReviewRequired,
			Result:         &resultText,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
	}

	response := &MediaEngineResponse{
		Success:        true,
		AnalysisJobID:  jobID,
		OrganizationID: organizationID,
		ProcessedAt:    time.Now().UTC(),
	}

	if err := validateAnalysisResultPersistence(
		context.Background(),
		source,
		response,
		bundle,
	); err != nil {
		t.Fatalf("expected valid document forensics persistence input, got %v", err)
	}
}

func TestValidateAnalysisResultPersistenceDocumentOCR(t *testing.T) {
	organizationID := uuid.New()
	jobID := uuid.New()
	assetID := uuid.New()
	modelID := uuid.New()
	modelVersionID := uuid.New()

	source := AnalysisSource{
		Asset: MediaAnalysisAsset{
			ID:             assetID,
			OrganizationID: organizationID,
			MediaType:      MediaTypeDocument,
		},
		Model: AnalysisModelReference{
			ModelID:        modelID,
			ModelVersionID: modelVersionID,
			ModelCode:      "DOC_OCR",
			ModelName:      "doc-ocr-model",
			ModelType:      JobTypeOCRExtraction,
			ModelStatus:    analysisModelStatusActive,
			VersionStatus:  analysisModelVersionStatusActive,
			IsDefault:      true,
			ModelFilePath:  "/tmp/ocr.onnx",
			ModelFileHash:  "def456",
		},
		Job: AIAnalysisJob{
			ID:               jobID,
			OrganizationID:   organizationID,
			MediaAssetID:     &assetID,
			AIModelID:        modelID,
			AIModelVersionID: modelVersionID,
			JobType:          JobTypeOCRExtraction,
			Priority:         JobPriorityNormal,
			Status:           JobStatusProcessing,
		},
	}

	resultText := "CLEAN"
	bundle := &AnalysisResultBundle{
		OCR: &OCRResult{
			ID:                       uuid.New(),
			AnalysisJobID:            jobID,
			OrganizationID:           organizationID,
			MediaAssetID:             &assetID,
			SourceMediaType:          MediaTypeDocument,
			ExtractionResult:         "TEXT_FOUND",
			OCREngine:                ptrString("TESSERACT"),
			DetectedLanguage:         ptrString("en"),
			ConfidenceScore:          ptrFloat64(88.1),
			WordCount:                ptrInt(523),
			CharacterCount:           ptrInt(3200),
			RequiresManualCorrection: false,
			CreatedAt:                time.Now().UTC(),
			UpdatedAt:                time.Now().UTC(),
		},
		EvidenceAnalysis: EvidenceAnalysis{
			ID:             uuid.New(),
			OrganizationID: organizationID,
			AnalysisJobID:  &jobID,
			MediaAssetID:   &assetID,
			AnalysisType:   JobTypeOCRExtraction,
			AnalysisMethod: AnalysisMethodAIBased,
			AnalysisStatus: AnalysisStatusCompleted,
			Result:         &resultText,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
	}

	response := &MediaEngineResponse{
		Success:        true,
		AnalysisJobID:  jobID,
		OrganizationID: organizationID,
		ProcessedAt:    time.Now().UTC(),
	}

	if err := validateAnalysisResultPersistence(
		context.Background(),
		source,
		response,
		bundle,
	); err != nil {
		t.Fatalf("expected valid OCR persistence input, got %v", err)
	}
}
