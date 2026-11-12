package deepfakeforensics

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const defaultMediaModelConfidenceThreshold = 50

// BuildMediaEngineRequest converts a claimed database job
// and its resolved organization asset/model into the strict
// request accepted by the offline Python analysis engine.
func BuildMediaEngineRequest(
	source AnalysisSource,
) (MediaEngineRequest, error) {
	if err := validateAnalysisSourceForEngine(
		source,
	); err != nil {
		return MediaEngineRequest{}, err
	}

	executionDevice := normalizedExecutionDevice(
		source.Job.ExecutionDevice,
	)
	if err := validateExecutionDeviceSupport(
		source.Model,
		executionDevice,
	); err != nil {
		return MediaEngineRequest{}, err
	}

	fileName := strings.TrimSpace(
		source.Asset.OriginalFileName,
	)
	if fileName == "" {
		fileName = strings.TrimSpace(
			source.Asset.StoredFileName,
		)
	}

	request := MediaEngineRequest{
		RequestID:     uuid.New(),
		RequestType:   mediaEngineRequestType,
		SchemaVersion: mediaEngineSchemaVersion,

		OrganizationID: source.Job.OrganizationID,
		AnalysisJobID:  source.Job.ID,

		MediaAssetID:   source.Job.MediaAssetID,
		EvidenceID:     source.Job.EvidenceID,
		EvidenceFileID: source.Job.EvidenceFileID,

		JobType:   NormalizeConstant(source.Job.JobType),
		MediaType: NormalizeConstant(source.Asset.MediaType),

		FileName:       fileName,
		MimeType:       strings.TrimSpace(source.Asset.MimeType),
		SourceFilePath: strings.TrimSpace(source.Asset.StoragePath),
		FileSizeBytes:  source.Asset.FileSizeBytes,
		FileHash: strings.ToLower(
			strings.TrimSpace(source.Asset.FileHash),
		),

		ExecutionDevice: executionDevice,

		Parameters: cloneRequestParameters(
			source.Job.RequestParameters,
		),

		RequestedAt: time.Now().UTC(),
	}

	if source.Model.IsInferenceReady() {
		request.Model = buildEngineModelSpecification(
			source.Model,
		)
	}

	if request.MediaType == MediaTypeImage {
		candidates := source.Models
		if len(candidates) < 2 {
			candidates = []AnalysisModelReference{source.Model}
		}
		readyModels := make([]AnalysisModelReference, 0, len(candidates))
		seenVersions := map[uuid.UUID]bool{}
		for _, model := range candidates {
			if seenVersions[model.ModelVersionID] || !model.IsInferenceReady() || !analysisModelMatchesJob(model, source.Job.JobType) {
				continue
			}
			if err := validateExecutionDeviceSupport(model, executionDevice); err != nil {
				continue
			}
			seenVersions[model.ModelVersionID] = true
			readyModels = append(readyModels, model)
		}
		if len(readyModels) >= 2 {
			request.Models = make([]MediaEngineModelSpecification, 0, len(readyModels))
			for _, model := range readyModels {
				request.Models = append(request.Models, *buildEngineModelSpecification(model))
			}
		}
	}

	if err := normalizeAndValidateEngineRequest(
		&request,
	); err != nil {
		return MediaEngineRequest{}, err
	}

	return request, nil
}

func validateAnalysisSourceForEngine(
	source AnalysisSource,
) error {
	if source.Job.ID == uuid.Nil ||
		source.Job.OrganizationID == uuid.Nil ||
		source.Job.MediaAssetID == nil ||
		*source.Job.MediaAssetID == uuid.Nil ||
		source.Asset.ID == uuid.Nil ||
		source.Asset.OrganizationID == uuid.Nil ||
		source.Model.ModelID == uuid.Nil ||
		source.Model.ModelVersionID == uuid.Nil ||
		source.Job.AIModelID == uuid.Nil ||
		source.Job.AIModelVersionID == uuid.Nil {
		return fmt.Errorf(
			"%w: incomplete analysis source",
			ErrInvalidRepositoryInput,
		)
	}

	if NormalizeConstant(source.Job.Status) !=
		JobStatusProcessing {
		return ErrAnalysisJobConflict
	}

	if source.Job.OrganizationID !=
		source.Asset.OrganizationID ||
		*source.Job.MediaAssetID !=
			source.Asset.ID ||
		source.Job.AIModelID !=
			source.Model.ModelID ||
		source.Job.AIModelVersionID !=
			source.Model.ModelVersionID {
		return fmt.Errorf(
			"%w: analysis source identity mismatch",
			ErrInvalidRepositoryInput,
		)
	}

	jobType := NormalizeConstant(
		source.Job.JobType,
	)
	mediaType := NormalizeConstant(
		source.Asset.MediaType,
	)
	if !IsSupportedJobType(jobType) ||
		!IsSupportedMediaType(mediaType) ||
		!jobSupportsMediaType(
			jobType,
			mediaType,
		) ||
		!analysisModelMatchesJob(source.Model, jobType) {
		return fmt.Errorf(
			"%w: incompatible job, media or model type",
			ErrInvalidRepositoryInput,
		)
	}

	if NormalizeConstant(source.Asset.Status) !=
		mediaAssetStatusAvailable ||
		strings.TrimSpace(
			source.Asset.StoragePath,
		) == "" ||
		strings.TrimSpace(
			source.Asset.MimeType,
		) == "" ||
		source.Asset.FileSizeBytes <= 0 ||
		strings.TrimSpace(
			source.Asset.FileHash,
		) == "" {
		return fmt.Errorf(
			"%w: media asset is unavailable for analysis",
			ErrInvalidRepositoryInput,
		)
	}

	if source.Model.MaximumFileSizeBytes != nil &&
		*source.Model.MaximumFileSizeBytes > 0 &&
		source.Asset.FileSizeBytes >
			*source.Model.MaximumFileSizeBytes {
		return fmt.Errorf(
			"%w: media file exceeds model size limit",
			ErrInvalidRepositoryInput,
		)
	}

	return nil
}

func normalizedExecutionDevice(
	value *string,
) string {
	if value == nil {
		return "CPU"
	}

	device := NormalizeConstant(*value)
	if device == "" {
		return "CPU"
	}

	return device
}

func validateExecutionDeviceSupport(
	model AnalysisModelReference,
	executionDevice string,
) error {
	switch NormalizeConstant(executionDevice) {
	case "CPU":
		if !model.SupportsCPU {
			return fmt.Errorf(
				"%w: selected model does not support CPU execution",
				ErrInvalidRepositoryInput,
			)
		}

	case "CUDA":
		if !model.SupportsGPU {
			return fmt.Errorf(
				"%w: selected model does not support CUDA execution",
				ErrInvalidRepositoryInput,
			)
		}

	case "AUTO":
		if !model.SupportsCPU &&
			!model.SupportsGPU {
			return fmt.Errorf(
				"%w: selected model has no supported execution device",
				ErrInvalidRepositoryInput,
			)
		}

	default:
		return fmt.Errorf(
			"%w: unsupported execution device",
			ErrInvalidRepositoryInput,
		)
	}

	return nil
}

func buildEngineModelSpecification(
	model AnalysisModelReference,
) *MediaEngineModelSpecification {
	confidenceThreshold :=
		float64(
			defaultMediaModelConfidenceThreshold,
		)
	if model.ConfidenceThreshold != nil &&
		*model.ConfidenceThreshold >= 0 &&
		*model.ConfidenceThreshold <= 100 {
		confidenceThreshold =
			*model.ConfidenceThreshold
	}

	configuration := cloneRequestParameters(model.Configuration)
	role := NormalizeConstant(fmt.Sprint(configuration["ensemble_role"]))
	if role == "" {
		switch NormalizeConstant(fmt.Sprint(configuration["detector_scope"])) {
		case JobTypeSyntheticImage:
			role = "SYNTHETIC_IMAGE"
		case JobTypeDeepfakeImage:
			role = "GENERAL_DEEPFAKE"
		}
		if role != "" {
			configuration["ensemble_role"] = role
		}
	}
	preprocessing := ""
	if configured, exists := configuration["preprocessing"]; exists && configured != nil {
		preprocessing = NormalizeConstant(fmt.Sprint(configured))
	}
	if preprocessing == "" {
		switch role {
		case "FACE_SWAP":
			configuration["preprocessing"] = "FACE_CONTEXT_CROP_V1"
			if _, exists := configuration["context_scale"]; !exists {
				configuration["context_scale"] = 2.35
			}
		case "WHOLE_IMAGE_AI":
			configuration["preprocessing"] = "WHOLE_IMAGE_RGB_V1"
		}
	}

	return &MediaEngineModelSpecification{
		ModelName: strings.TrimSpace(
			model.ModelName,
		),
		ModelVersion: strings.TrimSpace(
			model.VersionNumber,
		),

		ModelFormat: NormalizeConstant(
			model.ModelFormat,
		),
		ModelFilePath: strings.TrimSpace(
			model.ModelFilePath,
		),
		ModelFileHash: strings.ToLower(
			strings.TrimSpace(
				model.ModelFileHash,
			),
		),

		ConfidenceThreshold: confidenceThreshold,

		Configuration: configuration,
	}
}

func cloneRequestParameters(
	source map[string]any,
) map[string]any {
	if len(source) == 0 {
		return map[string]any{}
	}

	result := make(
		map[string]any,
		len(source),
	)
	for key, value := range source {
		result[key] = value
	}

	return result
}
