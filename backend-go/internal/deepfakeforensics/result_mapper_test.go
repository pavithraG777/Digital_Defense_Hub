package deepfakeforensics

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBuildAnalysisResultBundleDocumentForensics(t *testing.T) {
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
			FileHash:       "sha256:deadbeef",
		},
		Model: AnalysisModelReference{
			ModelID:        modelID,
			ModelVersionID: modelVersionID,
			ModelCode:      "DOC_FORNS",
			ModelName:      "doc-forensics-model",
			ModelType:      JobTypeDocumentForensics,
			ModelStatus:    analysisModelStatusActive,
			VersionStatus:  analysisModelVersionStatusActive,
			ModelFormat:    "ONNX",
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
			Status:           JobStatusCompleted,
		},
	}

	response := &MediaEngineResponse{
		RequestID:      uuid.New(),
		AnalysisJobID:  jobID,
		OrganizationID: organizationID,
		Success:        true,
		Runtime:        "ONNX_RUNTIME",
		ForensicsAssessment: &EngineForensicsAssessment{
			MediaType:           MediaTypeDocument,
			ForensicResult:      ForensicResultManipulated,
			ConfidenceScore:     93.7,
			AnalysisSummary:     "Document integrity check flagged manipulation",
			Findings:            []string{"embedded metadata mismatch"},
			SuspiciousLocations: []EngineSuspiciousRegion{{RegionType: "PAGE", PageNumber: ptrInt(4), Description: "modified header"}},
			ForensicFeatureData: map[string]any{"heuristics": "mismatch"},
		},
		ProcessingDurationMS: 1542,
		ProcessedAt:          time.Now().UTC(),
	}

	bundle, err := BuildAnalysisResultBundle(source, response)
	if err != nil {
		t.Fatalf("expected successful bundle build, got %v", err)
	}

	if bundle.Forensics == nil {
		t.Fatal("expected forensics result to be populated")
	}

	if bundle.Forensics.ForensicResult != ForensicResultManipulated {
		t.Fatalf("expected forensic result %s, got %s", ForensicResultManipulated, bundle.Forensics.ForensicResult)
	}

	if bundle.EvidenceAnalysis.Result == nil || *bundle.EvidenceAnalysis.Result != "MANIPULATED" {
		t.Fatalf("expected evidence analysis result MANIPULATED, got %v", bundle.EvidenceAnalysis.Result)
	}

	if NormalizeConstant(bundle.EvidenceAnalysis.AnalysisStatus) != AnalysisStatusReviewRequired {
		t.Fatalf("expected evidence analysis status %s, got %s", AnalysisStatusReviewRequired, bundle.EvidenceAnalysis.AnalysisStatus)
	}

	if len(bundle.Forensics.Findings) != 1 || bundle.Forensics.Findings[0] != "embedded metadata mismatch" {
		t.Fatalf("expected findings to include embedded metadata mismatch, got %v", bundle.Forensics.Findings)
	}
}

func TestBuildAnalysisResultBundleDocumentOCR(t *testing.T) {
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
			FileHash:       "sha256:cafebabe",
		},
		Model: AnalysisModelReference{
			ModelID:        modelID,
			ModelVersionID: modelVersionID,
			ModelCode:      "DOC_OCR",
			ModelName:      "doc-ocr-model",
			ModelType:      JobTypeOCRExtraction,
			ModelStatus:    analysisModelStatusActive,
			VersionStatus:  analysisModelVersionStatusActive,
			ModelFormat:    "ONNX",
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
			Status:           JobStatusCompleted,
		},
	}

	response := &MediaEngineResponse{
		RequestID:      uuid.New(),
		AnalysisJobID:  jobID,
		OrganizationID: organizationID,
		Success:        true,
		Runtime:        "TESSERACT",
		OCRAssessment: &EngineOCRAssessment{
			SourceMediaType:          MediaTypeDocument,
			ExtractionResult:         "TEXT_FOUND",
			OCREngine:                "TESSERACT",
			DetectedLanguage:         ptrString("en"),
			ConfidenceScore:          ptrFloat64(88.1),
			WordCount:                278,
			CharacterCount:           1700,
			RequiresManualCorrection: false,
		},
		ProcessingDurationMS: 612,
		ProcessedAt:          time.Now().UTC(),
	}

	bundle, err := BuildAnalysisResultBundle(source, response)
	if err != nil {
		t.Fatalf("expected successful OCR bundle build, got %v", err)
	}

	if bundle.OCR == nil {
		t.Fatal("expected OCR result to be populated")
	}

	if bundle.OCR.ExtractionResult != "TEXT_FOUND" {
		t.Fatalf("expected OCR extraction result TEXT_FOUND, got %s", bundle.OCR.ExtractionResult)
	}

	if bundle.EvidenceAnalysis.Result == nil || *bundle.EvidenceAnalysis.Result != "CLEAN" {
		t.Fatalf("expected evidence analysis result CLEAN, got %v", bundle.EvidenceAnalysis.Result)
	}

	if bundle.OCR.ConfidenceScore == nil || *bundle.OCR.ConfidenceScore != 88.1 {
		t.Fatalf("expected OCR confidence score 88.1, got %v", bundle.OCR.ConfidenceScore)
	}

	if bundle.OCR.DetectedLanguage == nil || *bundle.OCR.DetectedLanguage != "en" {
		t.Fatalf("expected detected language en, got %v", bundle.OCR.DetectedLanguage)
	}
}

func ptrInt(value int) *int {
	return &value
}

func TestMapConsistencyResultToBundle(t *testing.T) {
	source := AnalysisSource{
		Asset: MediaAnalysisAsset{
			ID:             uuid.New(),
			OrganizationID: uuid.New(),
			MediaType:      MediaTypeVideo,
			FileHash:       "deadbeef",
			FileSizeBytes:  123,
		},
		Model: AnalysisModelReference{
			ModelID:        uuid.New(),
			ModelVersionID: uuid.New(),
			ModelCode:      "consistency-model",
			ModelName:      "Consistency v1",
			ModelType:      JobTypeAudioVisualConsistency,
			ModelStatus:    "ACTIVE",
			Framework:      "PYTORCH",
			InputType:      "VIDEO",
			OutputType:     "CONSISTENCY",
			SupportsCPU:    true,
			SupportsGPU:    true,
			VersionNumber:  "1.0.0",
			ModelFilePath:  "/models/consistency.pt",
			ModelFileHash:  "abc",
			ModelFormat:    "PT",
			VersionStatus:  "ACTIVE",
			IsDefault:      true,
		},
		Job: AIAnalysisJob{
			ID:             uuid.New(),
			OrganizationID: uuid.New(),
			JobType:        JobTypeAudioVisualConsistency,
		},
	}

	resp := &MediaEngineResponse{
		RequestID:      uuid.New(),
		AnalysisJobID:  source.Job.ID,
		OrganizationID: source.Job.OrganizationID,
		Success:        true,
		Runtime:        "PYTORCH",
		ConsistencyAssessment: &EngineConsistencyAssessment{
			MediaType:         MediaTypeVideo,
			ConsistencyResult: "CLEAN",
			ConfidenceScore:   95.0,
			FeatureData:       map[string]any{"foo": "bar"},
			Signals:           []EngineAnalysisSignal{},
			SuspiciousRegions: []EngineSuspiciousRegion{},
		},
		ProcessingDurationMS: 100,
		ProcessedAt:          time.Now(),
	}

	bundle, err := BuildAnalysisResultBundle(source, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if bundle.Forensics == nil {
		t.Fatalf("expected forensics result to be populated")
	}
	if *bundle.Forensics.ConfidenceScore != 95.0 {
		t.Fatalf("expected confidence 95.0, got %v", bundle.Forensics.ConfidenceScore)
	}
}
