package deepfakeforensics

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrMediaEngineUnavailable = errors.New(
		"multimodal media analysis engine is unavailable",
	)

	ErrInvalidMediaEngineResponse = errors.New(
		"invalid multimodal media analysis engine response",
	)

	ErrMediaEngineExecutionFailed = errors.New(
		"multimodal media analysis execution failed",
	)
)

const (
	defaultMediaEngineTimeout = 5 * time.Minute

	maximumMediaEngineResponseSize = 64 * 1024 * 1024
	maximumMediaEngineErrorLength  = 2048
)

// EngineClient calls the authenticated offline Python
// multimodal media-analysis service.
type EngineClient struct {
	baseURL      *url.URL
	serviceToken string
	httpClient   *http.Client
}

func NewEngineClient(
	baseURL string,
	serviceToken string,
	timeout time.Duration,
) (*EngineClient, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, errors.New(
			"multimodal media engine URL is required",
		)
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf(
			"parse multimodal media engine URL: %w",
			err,
		)
	}

	if parsedURL.Scheme != "http" &&
		parsedURL.Scheme != "https" {
		return nil, errors.New(
			"multimodal media engine URL must use HTTP or HTTPS",
		)
	}
	if strings.TrimSpace(parsedURL.Host) == "" {
		return nil, errors.New(
			"multimodal media engine URL host is required",
		)
	}

	serviceToken = strings.TrimSpace(serviceToken)
	if serviceToken == "" {
		return nil, errors.New(
			"multimodal media engine service token is required",
		)
	}

	if timeout <= 0 {
		timeout = defaultMediaEngineTimeout
	}

	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""

	return &EngineClient{
		baseURL:      parsedURL,
		serviceToken: serviceToken,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (c *EngineClient) CheckHealth(
	ctx context.Context,
) (*MediaEngineHealthResponse, error) {
	if !c.isAvailable() || ctx == nil {
		return nil, ErrMediaEngineUnavailable
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.endpointURL(
			"/v1/media-forensics/health",
		),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create multimodal media health request: %w",
			err,
		)
	}

	c.setCommonHeaders(request)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrMediaEngineUnavailable,
			err,
		)
	}
	defer response.Body.Close()

	responseBody, err := readBoundedEngineResponse(
		response.Body,
	)
	if err != nil {
		return nil, err
	}

	if response.StatusCode < http.StatusOK ||
		response.StatusCode >=
			http.StatusMultipleChoices {
		return nil, engineHTTPError(
			response.StatusCode,
			response.Status,
			responseBody,
		)
	}

	var health MediaEngineHealthResponse
	if err = decodeStrictEngineJSON(
		responseBody,
		&health,
	); err != nil {
		return nil, err
	}

	health.Status = NormalizeConstant(
		health.Status,
	)
	if health.Status != "HEALTHY" {
		return nil, fmt.Errorf(
			"%w: engine health status is %s",
			ErrMediaEngineUnavailable,
			health.Status,
		)
	}

	return &health, nil
}

// Analyze submits one verified local file for offline
// multimodal analysis. A non-nil response may accompany
// ErrMediaEngineExecutionFailed so the worker can persist
// the engine failure details.
func (c *EngineClient) Analyze(
	ctx context.Context,
	engineRequest MediaEngineRequest,
) (*MediaEngineResponse, error) {
	if !c.isAvailable() || ctx == nil {
		return nil, ErrMediaEngineUnavailable
	}

	if err := normalizeAndValidateEngineRequest(
		&engineRequest,
	); err != nil {
		return nil, err
	}

	requestBody, err := json.Marshal(engineRequest)
	if err != nil {
		return nil, fmt.Errorf(
			"encode multimodal media request: %w",
			err,
		)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.endpointURL(
			"/v1/media-forensics/analyze",
		),
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create multimodal media request: %w",
			err,
		)
	}

	c.setCommonHeaders(request)
	request.Header.Set(
		"Content-Type",
		"application/json",
	)
	request.Header.Set(
		"X-Request-ID",
		engineRequest.RequestID.String(),
	)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrMediaEngineUnavailable,
			err,
		)
	}
	defer response.Body.Close()

	responseBody, err := readBoundedEngineResponse(
		response.Body,
	)
	if err != nil {
		return nil, err
	}

	if response.StatusCode < http.StatusOK ||
		response.StatusCode >=
			http.StatusMultipleChoices {
		return nil, engineHTTPError(
			response.StatusCode,
			response.Status,
			responseBody,
		)
	}

	var engineResponse MediaEngineResponse
	if err = decodeStrictEngineJSON(
		responseBody,
		&engineResponse,
	); err != nil {
		return nil, err
	}

	if err = validateEngineResponseIdentity(
		&engineResponse,
		engineRequest,
	); err != nil {
		return nil, err
	}

	if !engineResponse.Success {
		message := "offline media analysis failed"
		if engineResponse.ErrorMessage != nil &&
			strings.TrimSpace(
				*engineResponse.ErrorMessage,
			) != "" {
			message = strings.TrimSpace(
				*engineResponse.ErrorMessage,
			)
		}

		return &engineResponse, fmt.Errorf(
			"%w: %s",
			ErrMediaEngineExecutionFailed,
			message,
		)
	}

	if err = validateSuccessfulEngineResponse(
		&engineResponse,
		engineRequest.JobType,
	); err != nil {
		return nil, err
	}

	return &engineResponse, nil
}

func (c *EngineClient) isAvailable() bool {
	return c != nil &&
		c.baseURL != nil &&
		c.httpClient != nil &&
		strings.TrimSpace(c.serviceToken) != ""
}

func (c *EngineClient) setCommonHeaders(
	request *http.Request,
) {
	request.Header.Set(
		"Accept",
		"application/json",
	)
	request.Header.Set(
		"X-DDH-Service-Token",
		c.serviceToken,
	)
}

func (c *EngineClient) endpointURL(
	endpointPath string,
) string {
	resolvedURL := *c.baseURL
	resolvedURL.Path = strings.TrimRight(
		resolvedURL.Path,
		"/",
	) + "/" + strings.TrimLeft(
		endpointPath,
		"/",
	)
	resolvedURL.RawQuery = ""
	resolvedURL.Fragment = ""

	return resolvedURL.String()
}

func normalizeAndValidateEngineRequest(
	request *MediaEngineRequest,
) error {
	if request == nil {
		return ErrInvalidRepositoryInput
	}

	request.JobType = NormalizeConstant(
		request.JobType,
	)
	request.MediaType = NormalizeConstant(
		request.MediaType,
	)
	request.ExecutionDevice = NormalizeConstant(
		request.ExecutionDevice,
	)

	if request.RequestType == "" {
		request.RequestType =
			mediaEngineRequestType
	}
	if request.SchemaVersion == "" {
		request.SchemaVersion =
			mediaEngineSchemaVersion
	}
	if request.ExecutionDevice == "" {
		request.ExecutionDevice = "CPU"
	}
	if request.Parameters == nil {
		request.Parameters = map[string]any{}
	}
	if request.RequestedAt.IsZero() {
		request.RequestedAt = time.Now().UTC()
	} else {
		request.RequestedAt =
			request.RequestedAt.UTC()
	}

	hasSourceReference :=
		request.MediaAssetID != nil ||
			request.EvidenceID != nil

	if request.RequestID == uuid.Nil ||
		request.OrganizationID == uuid.Nil ||
		request.AnalysisJobID == uuid.Nil ||
		!hasSourceReference ||
		!IsSupportedJobType(request.JobType) ||
		!IsSupportedMediaType(request.MediaType) ||
		!jobSupportsMediaType(
			request.JobType,
			request.MediaType,
		) ||
		strings.TrimSpace(request.FileName) == "" ||
		strings.TrimSpace(request.MimeType) == "" ||
		strings.TrimSpace(
			request.SourceFilePath,
		) == "" ||
		request.FileSizeBytes <= 0 {
		return fmt.Errorf(
			"%w: incomplete multimodal media request",
			ErrInvalidRepositoryInput,
		)
	}

	if request.RequestType !=
		mediaEngineRequestType ||
		request.SchemaVersion !=
			mediaEngineSchemaVersion {
		return fmt.Errorf(
			"%w: unsupported multimodal schema",
			ErrInvalidRepositoryInput,
		)
	}

	if request.ExecutionDevice != "AUTO" &&
		request.ExecutionDevice != "CPU" &&
		request.ExecutionDevice != "CUDA" {
		return fmt.Errorf(
			"%w: unsupported execution device",
			ErrInvalidRepositoryInput,
		)
	}

	decodedHash, err := hex.DecodeString(
		strings.TrimSpace(request.FileHash),
	)
	if err != nil || len(decodedHash) != 32 {
		return fmt.Errorf(
			"%w: source SHA-256 hash is invalid",
			ErrInvalidRepositoryInput,
		)
	}
	request.FileHash = strings.ToLower(
		strings.TrimSpace(request.FileHash),
	)

	return nil
}

func jobSupportsMediaType(
	jobType string,
	mediaType string,
) bool {
	switch NormalizeConstant(jobType) {
	case JobTypeDeepfakeImage,
		JobTypeSyntheticImage,
		JobTypeImageForensics:
		return NormalizeConstant(mediaType) ==
			MediaTypeImage

	case JobTypeDeepfakeVideo,
		JobTypeVideoForensics:
		return NormalizeConstant(mediaType) ==
			MediaTypeVideo

	case JobTypeDeepfakeAudio,
		JobTypeAudioForensics:
		return NormalizeConstant(mediaType) ==
			MediaTypeAudio

	case JobTypeDocumentForensics:
		return NormalizeConstant(mediaType) ==
			MediaTypeDocument

	case JobTypeOCRExtraction:
		switch NormalizeConstant(mediaType) {
		case MediaTypeImage,
			MediaTypeVideo,
			MediaTypeDocument:
			return true
		}
	}

	return false
}

func validateEngineResponseIdentity(
	response *MediaEngineResponse,
	request MediaEngineRequest,
) error {
	if response == nil ||
		response.RequestID != request.RequestID ||
		response.AnalysisJobID !=
			request.AnalysisJobID ||
		response.OrganizationID !=
			request.OrganizationID ||
		response.ProcessingDurationMS < 0 ||
		response.ProcessedAt.IsZero() {
		return fmt.Errorf(
			"%w: response identity or metadata mismatch",
			ErrInvalidMediaEngineResponse,
		)
	}

	return nil
}

func validateSuccessfulEngineResponse(
	response *MediaEngineResponse,
	jobType string,
) error {
	runtime := NormalizeConstant(response.Runtime)
	switch runtime {
	case "PYTORCH",
		"ONNX_RUNTIME",
		"OPENCV",
		"TESSERACT",
		"HYBRID",
		"HEURISTIC_FALLBACK":
	default:
		return fmt.Errorf(
			"%w: unsupported runtime",
			ErrInvalidMediaEngineResponse,
		)
	}
	response.Runtime = runtime

	assessmentCount := 0
	if response.DeepfakeAssessment != nil {
		assessmentCount++
	}
	if response.ForensicsAssessment != nil {
		assessmentCount++
	}
	if response.OCRAssessment != nil {
		assessmentCount++
	}
	if response.ConsistencyAssessment != nil {
		assessmentCount++
	}
	if assessmentCount != 1 {
		return fmt.Errorf(
			"%w: exactly one assessment is required",
			ErrInvalidMediaEngineResponse,
		)
	}

	switch {
	case IsDeepfakeAssessmentJobType(jobType):
		if response.DeepfakeAssessment == nil {
			return fmt.Errorf(
				"%w: deepfake assessment is missing",
				ErrInvalidMediaEngineResponse,
			)
		}
		return validateDeepfakeAssessment(
			response.DeepfakeAssessment,
		)

	case IsForensicsJobType(jobType):
		if response.ForensicsAssessment == nil {
			return fmt.Errorf(
				"%w: forensic assessment is missing",
				ErrInvalidMediaEngineResponse,
			)
		}
		return validateForensicsAssessment(
			response.ForensicsAssessment,
		)

	case NormalizeConstant(jobType) ==
		JobTypeOCRExtraction:
		if response.OCRAssessment == nil {
			return fmt.Errorf(
				"%w: OCR assessment is missing",
				ErrInvalidMediaEngineResponse,
			)
		}
		return validateOCRAssessment(
			response.OCRAssessment,
		)

	case NormalizeConstant(jobType) == JobTypeAudioVisualConsistency,
		NormalizeConstant(jobType) == JobTypeLipSyncConsistency,
		NormalizeConstant(jobType) == JobTypeMetadataIntegrity:
		if response.ConsistencyAssessment == nil {
			return fmt.Errorf(
				"%w: consistency assessment is missing",
				ErrInvalidMediaEngineResponse,
			)
		}
		return validateConsistencyAssessment(
			response.ConsistencyAssessment,
		)
	}

	return fmt.Errorf(
		"%w: unsupported result job type",
		ErrInvalidMediaEngineResponse,
	)
}

func validateDeepfakeAssessment(
	assessment *EngineDeepfakeAssessment,
) error {
	if assessment == nil ||
		!IsSupportedMediaType(
			assessment.MediaType,
		) ||
		!validScore(
			assessment.DeepfakeProbability,
		) ||
		!validScore(
			assessment.AuthenticityProbability,
		) ||
		!validScore(
			assessment.ConfidenceScore,
		) ||
		math.Abs(
			assessment.DeepfakeProbability+
				assessment.AuthenticityProbability-
				100,
		) > 0.1 {
		return fmt.Errorf(
			"%w: invalid deepfake scores",
			ErrInvalidMediaEngineResponse,
		)
	}

	switch NormalizeConstant(
		assessment.DetectionResult,
	) {
	case DetectionResultAuthentic,
		DetectionResultLikelyAuthentic,
		DetectionResultSuspicious,
		DetectionResultLikelyDeepfake,
		DetectionResultDeepfake,
		DetectionResultInconclusive,
		DetectionResultError:
	default:
		return fmt.Errorf(
			"%w: unsupported deepfake result",
			ErrInvalidMediaEngineResponse,
		)
	}

	assessment.MediaType = NormalizeConstant(
		assessment.MediaType,
	)
	assessment.DetectionResult = NormalizeConstant(
		assessment.DetectionResult,
	)

	return nil
}

func validateConsistencyAssessment(
	assessment *EngineConsistencyAssessment,
) error {
	if assessment == nil ||
		!IsSupportedMediaType(assessment.MediaType) ||
		strings.TrimSpace(assessment.ConsistencyResult) == "" ||
		!validScore(assessment.ConfidenceScore) {
		return fmt.Errorf(
			"%w: invalid consistency assessment",
			ErrInvalidMediaEngineResponse,
		)
	}

	assessment.MediaType = NormalizeConstant(
		assessment.MediaType,
	)
	assessment.ConsistencyResult = NormalizeConstant(
		assessment.ConsistencyResult,
	)

	return nil
}

func validateForensicsAssessment(
	assessment *EngineForensicsAssessment,
) error {
	if assessment == nil ||
		!IsSupportedMediaType(
			assessment.MediaType,
		) ||
		!validScore(
			assessment.ConfidenceScore,
		) {
		return fmt.Errorf(
			"%w: invalid forensic assessment",
			ErrInvalidMediaEngineResponse,
		)
	}

	switch NormalizeConstant(
		assessment.ForensicResult,
	) {
	case ForensicResultAuthentic,
		ForensicResultSuspicious,
		ForensicResultManipulated,
		ForensicResultCorrupted,
		ForensicResultInconclusive,
		ForensicResultError:
	default:
		return fmt.Errorf(
			"%w: unsupported forensic result",
			ErrInvalidMediaEngineResponse,
		)
	}

	assessment.MediaType = NormalizeConstant(
		assessment.MediaType,
	)
	assessment.ForensicResult = NormalizeConstant(
		assessment.ForensicResult,
	)

	return nil
}

func validateOCRAssessment(
	assessment *EngineOCRAssessment,
) error {
	if assessment == nil {
		return fmt.Errorf(
			"%w: OCR assessment is required",
			ErrInvalidMediaEngineResponse,
		)
	}

	switch NormalizeConstant(
		assessment.SourceMediaType,
	) {
	case MediaTypeImage,
		MediaTypeVideo,
		MediaTypeDocument:
	default:
		return fmt.Errorf(
			"%w: unsupported OCR source type",
			ErrInvalidMediaEngineResponse,
		)
	}

	switch NormalizeConstant(
		assessment.ExtractionResult,
	) {
	case "TEXT_FOUND",
		"NO_TEXT",
		"PARTIAL",
		"INCONCLUSIVE",
		"ERROR":
	default:
		return fmt.Errorf(
			"%w: unsupported OCR result",
			ErrInvalidMediaEngineResponse,
		)
	}

	if assessment.ConfidenceScore != nil &&
		!validScore(
			*assessment.ConfidenceScore,
		) {
		return fmt.Errorf(
			"%w: invalid OCR confidence score",
			ErrInvalidMediaEngineResponse,
		)
	}

	assessment.SourceMediaType = NormalizeConstant(
		assessment.SourceMediaType,
	)
	assessment.ExtractionResult = NormalizeConstant(
		assessment.ExtractionResult,
	)

	return nil
}

func validScore(value float64) bool {
	return !math.IsNaN(value) &&
		!math.IsInf(value, 0) &&
		value >= 0 &&
		value <= 100
}

func readBoundedEngineResponse(
	body io.Reader,
) ([]byte, error) {
	responseBody, err := io.ReadAll(
		io.LimitReader(
			body,
			maximumMediaEngineResponseSize+1,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read multimodal media response: %w",
			err,
		)
	}

	if len(responseBody) >
		maximumMediaEngineResponseSize {
		return nil, fmt.Errorf(
			"%w: response exceeds maximum size",
			ErrInvalidMediaEngineResponse,
		)
	}

	return responseBody, nil
}

func decodeStrictEngineJSON(
	data []byte,
	destination any,
) error {
	decoder := json.NewDecoder(
		bytes.NewReader(data),
	)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(
		destination,
	); err != nil {
		return fmt.Errorf(
			"%w: decode response: %v",
			ErrInvalidMediaEngineResponse,
			err,
		)
	}

	var trailingValue any
	if err := decoder.Decode(
		&trailingValue,
	); !errors.Is(err, io.EOF) {
		return fmt.Errorf(
			"%w: response contains trailing data",
			ErrInvalidMediaEngineResponse,
		)
	}

	return nil
}

func engineHTTPError(
	statusCode int,
	statusText string,
	responseBody []byte,
) error {
	message := strings.TrimSpace(
		string(responseBody),
	)
	if message == "" {
		message = statusText
	}
	if len(message) > maximumMediaEngineErrorLength {
		message = message[:maximumMediaEngineErrorLength]
	}

	return fmt.Errorf(
		"%w: HTTP %d: %s",
		ErrMediaEngineUnavailable,
		statusCode,
		message,
	)
}
