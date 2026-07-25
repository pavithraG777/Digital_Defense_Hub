package preencryption

import (
	"bytes"
	"context"
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
	ErrDetectionEngineUnavailable = errors.New(
		"pre-encryption detection engine is unavailable",
	)

	ErrInvalidDetectionEngineResponse = errors.New(
		"invalid pre-encryption detection engine response",
	)
)

const (
	defaultPreEncryptionEngineTimeout = 15 * time.Second

	maximumPreEncryptionResponseSize = 2 * 1024 * 1024
)

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
	baseURL = strings.TrimSpace(
		baseURL,
	)

	if baseURL == "" {
		return nil, errors.New(
			"pre-encryption engine URL is required",
		)
	}

	parsedURL, err := url.Parse(
		baseURL,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse pre-encryption engine URL: %w",
			err,
		)
	}

	if parsedURL.Scheme != "http" &&
		parsedURL.Scheme != "https" {
		return nil, errors.New(
			"pre-encryption engine URL must use HTTP or HTTPS",
		)
	}

	if strings.TrimSpace(
		parsedURL.Host,
	) == "" {
		return nil, errors.New(
			"pre-encryption engine URL host is required",
		)
	}

	serviceToken = strings.TrimSpace(
		serviceToken,
	)

	if serviceToken == "" {
		return nil, errors.New(
			"pre-encryption service token is required",
		)
	}

	if timeout <= 0 {
		timeout =
			defaultPreEncryptionEngineTimeout
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
) error {
	if c == nil ||
		c.baseURL == nil ||
		c.httpClient == nil {
		return ErrDetectionEngineUnavailable
	}

	request, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			c.endpointURL("/health"),
			nil,
		)
	if err != nil {
		return fmt.Errorf(
			"create pre-encryption health request: %w",
			err,
		)
	}

	request.Header.Set(
		"Accept",
		"application/json",
	)

	request.Header.Set(
		"X-DDH-Service-Token",
		c.serviceToken,
	)

	response, err :=
		c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf(
			"%w: %v",
			ErrDetectionEngineUnavailable,
			err,
		)
	}
	defer response.Body.Close()

	_, _ = io.Copy(
		io.Discard,
		io.LimitReader(
			response.Body,
			maximumPreEncryptionResponseSize,
		),
	)

	if response.StatusCode <
		http.StatusOK ||
		response.StatusCode >=
			http.StatusMultipleChoices {
		return fmt.Errorf(
			"%w: health endpoint returned HTTP %d",
			ErrDetectionEngineUnavailable,
			response.StatusCode,
		)
	}

	return nil
}

func (c *EngineClient) Assess(
	ctx context.Context,
	engineRequest DetectionEngineRequest,
) (*DetectionEngineAssessment, error) {
	if c == nil ||
		c.baseURL == nil ||
		c.httpClient == nil {
		return nil, ErrDetectionEngineUnavailable
	}

	if engineRequest.RequestID ==
		uuid.Nil {
		return nil, errors.New(
			"pre-encryption request ID is required",
		)
	}

	if engineRequest.OrganizationID ==
		uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if engineRequest.DetectionID ==
		uuid.Nil {
		return nil, errors.New(
			"detection ID is required",
		)
	}

	engineRequest.WindowFingerprint =
		strings.TrimSpace(
			engineRequest.WindowFingerprint,
		)

	if len(
		engineRequest.WindowFingerprint,
	) < 32 {
		return nil, errors.New(
			"detection window fingerprint is invalid",
		)
	}

	if !IsValidScore(
		engineRequest.RuleScore,
	) {
		return nil, errors.New(
			"rule score must be between 0 and 100",
		)
	}

	if engineRequest.RequestType == "" {
		engineRequest.RequestType =
			DetectionEngineRequestType
	}

	if engineRequest.SchemaVersion == "" {
		engineRequest.SchemaVersion =
			DetectionFeatureSchemaVersion
	}

	if engineRequest.RequestType !=
		DetectionEngineRequestType {
		return nil, errors.New(
			"unsupported pre-encryption request type",
		)
	}

	if engineRequest.SchemaVersion !=
		DetectionFeatureSchemaVersion {
		return nil, errors.New(
			"unsupported pre-encryption schema version",
		)
	}

	if engineRequest.RequestedAt.IsZero() {
		engineRequest.RequestedAt =
			time.Now().UTC()
	} else {
		engineRequest.RequestedAt =
			engineRequest.RequestedAt.UTC()
	}

	requestBody, err := json.Marshal(
		engineRequest,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode pre-encryption request: %w",
			err,
		)
	}

	request, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			c.endpointURL(
				"/v1/ransomware/pre-encryption",
			),
			bytes.NewReader(
				requestBody,
			),
		)
	if err != nil {
		return nil, fmt.Errorf(
			"create pre-encryption request: %w",
			err,
		)
	}

	request.Header.Set(
		"Accept",
		"application/json",
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)

	request.Header.Set(
		"X-DDH-Service-Token",
		c.serviceToken,
	)

	request.Header.Set(
		"X-Request-ID",
		engineRequest.RequestID.String(),
	)

	response, err :=
		c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrDetectionEngineUnavailable,
			err,
		)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			maximumPreEncryptionResponseSize+1,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read pre-encryption response: %w",
			err,
		)
	}

	if len(responseBody) >
		maximumPreEncryptionResponseSize {
		return nil, fmt.Errorf(
			"%w: response exceeds maximum size",
			ErrInvalidDetectionEngineResponse,
		)
	}

	if response.StatusCode <
		http.StatusOK ||
		response.StatusCode >=
			http.StatusMultipleChoices {
		errorMessage := strings.TrimSpace(
			string(responseBody),
		)

		if errorMessage == "" {
			errorMessage =
				response.Status
		}

		return nil, fmt.Errorf(
			"%w: HTTP %d: %s",
			ErrDetectionEngineUnavailable,
			response.StatusCode,
			errorMessage,
		)
	}

	var engineResponse DetectionEngineResponse

	decoder := json.NewDecoder(
		bytes.NewReader(
			responseBody,
		),
	)

	decoder.DisallowUnknownFields()

	if err = decoder.Decode(
		&engineResponse,
	); err != nil {
		return nil, fmt.Errorf(
			"%w: decode response: %v",
			ErrInvalidDetectionEngineResponse,
			err,
		)
	}

	var trailingValue any

	if err = decoder.Decode(
		&trailingValue,
	); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf(
			"%w: response contains trailing data",
			ErrInvalidDetectionEngineResponse,
		)
	}

	if engineResponse.RequestID !=
		engineRequest.RequestID {
		return nil, fmt.Errorf(
			"%w: request ID mismatch",
			ErrInvalidDetectionEngineResponse,
		)
	}

	if !engineResponse.Success {
		errorMessage :=
			"pre-encryption assessment failed"

		if engineResponse.ErrorMessage != nil &&
			strings.TrimSpace(
				*engineResponse.ErrorMessage,
			) != "" {
			errorMessage =
				strings.TrimSpace(
					*engineResponse.ErrorMessage,
				)
		}

		return nil, fmt.Errorf(
			"%w: %s",
			ErrDetectionEngineUnavailable,
			errorMessage,
		)
	}

	if engineResponse.Assessment == nil {
		return nil, fmt.Errorf(
			"%w: assessment is missing",
			ErrInvalidDetectionEngineResponse,
		)
	}

	if err = validateDetectionEngineAssessment(
		engineResponse.Assessment,
	); err != nil {
		return nil, err
	}

	return engineResponse.Assessment, nil
}

func (c *EngineClient) endpointURL(
	endpointPath string,
) string {
	resolvedURL := *c.baseURL

	resolvedURL.Path =
		strings.TrimRight(
			resolvedURL.Path,
			"/",
		) +
			"/" +
			strings.TrimLeft(
				endpointPath,
				"/",
			)

	resolvedURL.RawQuery = ""
	resolvedURL.Fragment = ""

	return resolvedURL.String()
}

func validateDetectionEngineAssessment(
	assessment *DetectionEngineAssessment,
) error {
	if assessment == nil {
		return fmt.Errorf(
			"%w: assessment is required",
			ErrInvalidDetectionEngineResponse,
		)
	}

	scoreValues := []struct {
		name  string
		value float64
	}{
		{
			name:  "ai_score",
			value: assessment.AIScore,
		},
		{
			name:  "combined_risk_score",
			value: assessment.CombinedRiskScore,
		},
		{
			name:  "threat_probability",
			value: assessment.ThreatProbability,
		},
		{
			name:  "confidence_score",
			value: assessment.ConfidenceScore,
		},
	}

	for _, scoreValue := range scoreValues {
		if !IsValidScore(
			scoreValue.value,
		) {
			return fmt.Errorf(
				"%w: %s must be between 0 and 100",
				ErrInvalidDetectionEngineResponse,
				scoreValue.name,
			)
		}
	}

	assessment.RiskLevel =
		NormalizeConstant(
			assessment.RiskLevel,
		)

	expectedRiskLevel, valid :=
		RiskLevelFromScore(
			assessment.CombinedRiskScore,
		)
	if !valid ||
		assessment.RiskLevel !=
			expectedRiskLevel {
		return fmt.Errorf(
			"%w: risk level does not match combined score",
			ErrInvalidDetectionEngineResponse,
		)
	}

	assessment.Classification =
		NormalizeConstant(
			assessment.Classification,
		)

	expectedClassification :=
		classificationFromDetectionScore(
			assessment.CombinedRiskScore,
		)

	if assessment.Classification !=
		expectedClassification {
		return fmt.Errorf(
			"%w: classification does not match combined score",
			ErrInvalidDetectionEngineResponse,
		)
	}

	assessment.DetectionStage =
		NormalizeConstant(
			assessment.DetectionStage,
		)

	if !IsSupportedDetectionStage(
		assessment.DetectionStage,
	) {
		return fmt.Errorf(
			"%w: unsupported detection stage",
			ErrInvalidDetectionEngineResponse,
		)
	}

	assessment.ScoreExplanation =
		strings.TrimSpace(
			assessment.ScoreExplanation,
		)

	assessment.ModelName =
		strings.TrimSpace(
			assessment.ModelName,
		)

	assessment.ModelVersion =
		strings.TrimSpace(
			assessment.ModelVersion,
		)

	assessment.PolicyVersion =
		strings.TrimSpace(
			assessment.PolicyVersion,
		)

	if assessment.ScoreExplanation == "" ||
		assessment.ModelName == "" ||
		assessment.ModelVersion == "" ||
		assessment.PolicyVersion == "" {
		return fmt.Errorf(
			"%w: assessment metadata is incomplete",
			ErrInvalidDetectionEngineResponse,
		)
	}

	if len(assessment.RiskFactors) == 0 {
		return fmt.Errorf(
			"%w: risk factors are required",
			ErrInvalidDetectionEngineResponse,
		)
	}

	for index := range assessment.RiskFactors {
		factor :=
			&assessment.RiskFactors[index]

		factor.Code =
			NormalizeConstant(
				factor.Code,
			)

		factor.Name =
			strings.TrimSpace(
				factor.Name,
			)

		factor.Category =
			NormalizeConstant(
				factor.Category,
			)

		factor.Description =
			strings.TrimSpace(
				factor.Description,
			)

		if factor.Code == "" ||
			factor.Name == "" ||
			factor.Category == "" {
			return fmt.Errorf(
				"%w: risk factor %d is incomplete",
				ErrInvalidDetectionEngineResponse,
				index,
			)
		}

		if math.IsNaN(factor.Weight) ||
			math.IsInf(
				factor.Weight,
				0,
			) ||
			factor.Weight < 0 ||
			factor.Weight > 1 {
			return fmt.Errorf(
				"%w: risk factor %d weight is invalid",
				ErrInvalidDetectionEngineResponse,
				index,
			)
		}

		if !IsValidScore(
			factor.Score,
		) ||
			!IsValidScore(
				factor.Contribution,
			) {
			return fmt.Errorf(
				"%w: risk factor %d score is invalid",
				ErrInvalidDetectionEngineResponse,
				index,
			)
		}

		if factor.SignalCount < 0 {
			return fmt.Errorf(
				"%w: risk factor %d signal count is invalid",
				ErrInvalidDetectionEngineResponse,
				index,
			)
		}
	}

	if len(
		assessment.RecommendedActions,
	) == 0 {
		return fmt.Errorf(
			"%w: recommended actions are required",
			ErrInvalidDetectionEngineResponse,
		)
	}

	for index := range assessment.RecommendedActions {
		action :=
			&assessment.RecommendedActions[index]

		action.Code =
			NormalizeConstant(
				action.Code,
			)

		action.Title =
			strings.TrimSpace(
				action.Title,
			)

		action.Description =
			strings.TrimSpace(
				action.Description,
			)

		action.Priority =
			NormalizeConstant(
				action.Priority,
			)

		if action.Code == "" ||
			action.Title == "" ||
			action.Description == "" ||
			!IsSupportedRiskLevel(
				action.Priority,
			) {
			return fmt.Errorf(
				"%w: recommended action %d is invalid",
				ErrInvalidDetectionEngineResponse,
				index,
			)
		}
	}

	return nil
}
