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

func TestBuildMediaEngineRequestIncludesSpecializedImageEnsemble(t *testing.T) {
	organizationID, assetID, jobID := uuid.New(), uuid.New(), uuid.New()
	threshold := 66.0
	whole := AnalysisModelReference{
		ModelID: uuid.New(), ModelVersionID: uuid.New(), ModelName: "Whole image AI detector",
		ModelType: JobTypeDeepfakeImage, ModelStatus: analysisModelStatusActive,
		InputType: MediaTypeImage, SupportsCPU: true, VersionNumber: "2.0.0",
		ModelFilePath: "models/whole.pth", ModelFileHash: strings.Repeat("a", 64),
		ModelFormat: "PTH", VersionStatus: analysisModelVersionStatusActive, IsDefault: true,
		ConfidenceThreshold: &threshold, Configuration: map[string]any{"ensemble_role": "WHOLE_IMAGE_AI"},
	}
	face := whole
	face.ModelID, face.ModelVersionID = uuid.New(), uuid.New()
	face.ModelName, face.ModelFilePath, face.ModelFileHash = "Face swap detector", "models/face.pth", strings.Repeat("b", 64)
	face.Configuration = map[string]any{"ensemble_role": "FACE_SWAP", "preprocessing": ""}
	job := AIAnalysisJob{
		ID: jobID, OrganizationID: organizationID, MediaAssetID: &assetID,
		AIModelID: whole.ModelID, AIModelVersionID: whole.ModelVersionID,
		JobType: JobTypeDeepfakeImage, Status: JobStatusProcessing,
	}
	source := AnalysisSource{
		Asset: MediaAnalysisAsset{ID: assetID, OrganizationID: organizationID, OriginalFileName: "photo.jpg", StoragePath: "data/photo.jpg", MediaType: MediaTypeImage, MimeType: "image/jpeg", FileSizeBytes: 1024, FileHash: strings.Repeat("c", 64), Status: mediaAssetStatusAvailable},
		Model: whole, Models: []AnalysisModelReference{whole, face}, Job: job,
	}
	request, err := BuildMediaEngineRequest(source)
	if err != nil {
		t.Fatalf("expected ensemble request, got %v", err)
	}
	if len(request.Models) != 2 {
		t.Fatalf("expected two deduplicated ensemble models, got %d", len(request.Models))
	}
	if request.Models[1].Configuration["ensemble_role"] != "FACE_SWAP" {
		t.Fatalf("expected face-swap model configuration, got %#v", request.Models[1].Configuration)
	}
	if request.Models[1].Configuration["preprocessing"] != "FACE_CONTEXT_CROP_V1" {
		t.Fatalf("expected inferred face preprocessing, got %#v", request.Models[1].Configuration)
	}
}
