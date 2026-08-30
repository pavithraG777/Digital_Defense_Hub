package deepfakeforensics

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBuildMediaEngineRequestForDocumentForensics(t *testing.T) {
	organizationID := uuid.New()
	mediaAssetID := uuid.New()
	modelID := uuid.New()
	modelVersionID := uuid.New()
	jobID := uuid.New()

	asset := MediaAnalysisAsset{
		ID:               mediaAssetID,
		OrganizationID:   organizationID,
		OriginalFileName: "sample.pdf",
		StoredFileName:   "sample.pdf",
		StoragePath:      "/tmp/sample.pdf",
		MediaType:        MediaTypeDocument,
		MimeType:         "application/pdf",
		FileSizeBytes:    1024,
		FileHash:         strings.Repeat("a", 64),
		HashAlgorithm:    "SHA256",
		Status:           mediaAssetStatusAvailable,
		UploadedAt:       time.Now().UTC(),
	}

	model := AnalysisModelReference{
		ModelID:              modelID,
		ModelVersionID:       modelVersionID,
		ModelCode:            "DOC_FOR_1",
		ModelName:            "DocumentForensicsV1",
		ModelType:            JobTypeDocumentForensics,
		ModelStatus:          analysisModelStatusActive,
		Framework:            "ONNX",
		InputType:            "DOCUMENT",
		OutputType:           "CLASSIFICATION",
		SupportsCPU:          true,
		SupportsGPU:          false,
		MaximumFileSizeBytes: func() *int64 { v := int64(10_485_760); return &v }(),
		VersionNumber:        "1.0.0",
		ModelFilePath:        "models/doc_forensics.onnx",
		ModelFileHash:        strings.Repeat("b", 64),
		ModelFormat:          "ONNX",
		VersionStatus:        analysisModelVersionStatusActive,
		IsDefault:            true,
	}

	job := AIAnalysisJob{
		ID:                jobID,
		OrganizationID:    organizationID,
		MediaAssetID:      &mediaAssetID,
		AIModelID:         modelID,
		AIModelVersionID:  modelVersionID,
		JobType:           JobTypeDocumentForensics,
		Status:            JobStatusProcessing,
		RequestedBy:       nil,
		RequestParameters: map[string]any{"analysis_mode": AnalysisModeForensics},
	}

	source := AnalysisSource{
		Asset: asset,
		Model: model,
		Job:   job,
	}

	engineRequest, err := BuildMediaEngineRequest(source)
	if err != nil {
		t.Fatalf("expected request to build successfully, got %v", err)
	}

	if engineRequest.JobType != JobTypeDocumentForensics {
		t.Fatalf("expected request job type %s, got %s", JobTypeDocumentForensics, engineRequest.JobType)
	}
	if engineRequest.MediaType != MediaTypeDocument {
		t.Fatalf("expected request media type %s, got %s", MediaTypeDocument, engineRequest.MediaType)
	}
	if engineRequest.Model == nil {
		t.Fatal("expected model specification to be included for an inference-ready model")
	}
	if engineRequest.Model.ModelFormat != "ONNX" {
		t.Fatalf("expected model format ONNX, got %s", engineRequest.Model.ModelFormat)
	}
}

func TestBuildMediaEngineRequestForDocumentOCR(t *testing.T) {
	organizationID := uuid.New()
	mediaAssetID := uuid.New()
	modelID := uuid.New()
	modelVersionID := uuid.New()
	jobID := uuid.New()

	asset := MediaAnalysisAsset{
		ID:               mediaAssetID,
		OrganizationID:   organizationID,
		OriginalFileName: "sample.pdf",
		StoredFileName:   "sample.pdf",
		StoragePath:      "/tmp/sample.pdf",
		MediaType:        MediaTypeDocument,
		MimeType:         "application/pdf",
		FileSizeBytes:    2048,
		FileHash:         strings.Repeat("c", 64),
		HashAlgorithm:    "SHA256",
		Status:           mediaAssetStatusAvailable,
		UploadedAt:       time.Now().UTC(),
	}

	model := AnalysisModelReference{
		ModelID:        modelID,
		ModelVersionID: modelVersionID,
		ModelCode:      "OCR_DOC_1",
		ModelName:      "DocumentOCRV1",
		ModelType:      JobTypeOCRExtraction,
		ModelStatus:    analysisModelStatusActive,
		Framework:      "ONNX",
		InputType:      "DOCUMENT",
		OutputType:     "TEXT_EXTRACTION",
		SupportsCPU:    true,
		SupportsGPU:    false,
		VersionNumber:  "1.0.0",
		ModelFilePath:  "models/doc_ocr.onnx",
		ModelFileHash:  strings.Repeat("d", 64),
		ModelFormat:    "ONNX",
		VersionStatus:  analysisModelVersionStatusActive,
		IsDefault:      true,
	}

	job := AIAnalysisJob{
		ID:                jobID,
		OrganizationID:    organizationID,
		MediaAssetID:      &mediaAssetID,
		AIModelID:         modelID,
		AIModelVersionID:  modelVersionID,
		JobType:           JobTypeOCRExtraction,
		Status:            JobStatusProcessing,
		RequestedBy:       nil,
		RequestParameters: map[string]any{"analysis_mode": AnalysisModeOCR},
	}

	source := AnalysisSource{
		Asset: asset,
		Model: model,
		Job:   job,
	}

	engineRequest, err := BuildMediaEngineRequest(source)
	if err != nil {
		t.Fatalf("expected OCR request to build successfully, got %v", err)
	}

	if engineRequest.JobType != JobTypeOCRExtraction {
		t.Fatalf("expected request job type %s, got %s", JobTypeOCRExtraction, engineRequest.JobType)
	}
	if engineRequest.MediaType != MediaTypeDocument {
		t.Fatalf("expected request media type %s, got %s", MediaTypeDocument, engineRequest.MediaType)
	}
}
