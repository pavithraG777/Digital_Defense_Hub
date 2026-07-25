package airisk

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
	ErrRiskEngineUnavailable = errors.New(
		"AI Risk Scoring Engine is unavailable",
	)

	ErrInvalidRiskEngineResponse = errors.New(
		"invalid AI Risk Scoring Engine response",
	)
)

const (
	defaultRiskEngineTimeout      = 15 * time.Second
	maximumRiskEngineResponseSize = 2 * 1024 * 1024
)

type RiskEngineClient struct {
	baseURL      *url.URL
	serviceToken string
	httpClient   *http.Client
}

func NewRiskEngineClient(
	baseURL string,
	serviceToken string,
	timeout time.Duration,
) (*RiskEngineClient, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, errors.New(
			"AI Risk Scoring Engine URL is required",
		)
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf(
			"parse AI Risk Scoring Engine URL: %w",
			err,
		)
	}

	if parsedURL.Scheme != "http" &&
		parsedURL.Scheme != "https" {
		return nil, errors.New(
			"AI Risk Scoring Engine URL must use HTTP or HTTPS",
		)
	}

	if strings.TrimSpace(parsedURL.Host) == "" {
		return nil, errors.New(
			"AI Risk Scoring Engine URL host is required",
		)
	}

	serviceToken = strings.TrimSpace(serviceToken)
	if serviceToken == "" {
		return nil, errors.New(
			"AI Risk Scoring Engine service token is required",
		)
	}

	if timeout <= 0 {
		timeout = defaultRiskEngineTimeout
	}

	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""

	return &RiskEngineClient{
		baseURL:      parsedURL,
		serviceToken: serviceToken,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (c *RiskEngineClient) CheckHealth(
	ctx context.Context,
) error {
	if c == nil ||
		c.baseURL == nil ||
		c.httpClient == nil {
		return ErrRiskEngineUnavailable
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.endpointURL("/health"),
		nil,
	)
	if err != nil {
		return fmt.Errorf(
			"create AI Risk Scoring Engine health request: %w",
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

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf(
			"%w: %v",
			ErrRiskEngineUnavailable,
			err,
		)
	}
	defer response.Body.Close()

	_, _ = io.Copy(
		io.Discard,
		io.LimitReader(
			response.Body,
			maximumRiskEngineResponseSize,
		),
	)

	if response.StatusCode < http.StatusOK ||
		response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf(
			"%w: health endpoint returned HTTP %d",
			ErrRiskEngineUnavailable,
			response.StatusCode,
		)
	}

	return nil
}

func (c *RiskEngineClient) AssessIncidentRisk(
	ctx context.Context,
	engineRequest RiskEngineRequest,
) (*RiskEngineAssessment, error) {
	if c == nil ||
		c.baseURL == nil ||
		c.httpClient == nil {
		return nil, ErrRiskEngineUnavailable
	}

	if engineRequest.RequestID == uuid.Nil {
		return nil, errors.New(
			"AI risk request ID is required",
		)
	}

	if engineRequest.OrganizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	if engineRequest.IncidentID == uuid.Nil {
		return nil, errors.New(
			"incident ID is required",
		)
	}

	if engineRequest.RequestType == "" {
		engineRequest.RequestType =
			RiskEngineRequestTypeIncidentRansomware
	}

	if engineRequest.SchemaVersion == "" {
		engineRequest.SchemaVersion =
			RiskFeatureSchemaVersion
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
			"encode AI risk request: %w",
			err,
		)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.endpointURL("/v1/risk/incident"),
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create AI risk request: %w",
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

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrRiskEngineUnavailable,
			err,
		)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			maximumRiskEngineResponseSize+1,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read AI risk response: %w",
			err,
		)
	}

	if len(responseBody) >
		maximumRiskEngineResponseSize {
		return nil, fmt.Errorf(
			"%w: response exceeds maximum size",
			ErrInvalidRiskEngineResponse,
		)
	}

	if response.StatusCode < http.StatusOK ||
		response.StatusCode >= http.StatusMultipleChoices {
		errorMessage := strings.TrimSpace(
			string(responseBody),
		)

		if errorMessage == "" {
			errorMessage = response.Status
		}

		return nil, fmt.Errorf(
			"%w: HTTP %d: %s",
			ErrRiskEngineUnavailable,
			response.StatusCode,
			errorMessage,
		)
	}

	var engineResponse RiskEngineResponse

	decoder := json.NewDecoder(
		bytes.NewReader(responseBody),
	)
	decoder.DisallowUnknownFields()

	if err = decoder.Decode(
		&engineResponse,
	); err != nil {
		return nil, fmt.Errorf(
			"%w: decode response: %v",
			ErrInvalidRiskEngineResponse,
			err,
		)
	}

	if engineResponse.RequestID !=
		engineRequest.RequestID {
		return nil, fmt.Errorf(
			"%w: request ID mismatch",
			ErrInvalidRiskEngineResponse,
		)
	}

	if !engineResponse.Success {
		errorMessage := "risk assessment failed"

		if engineResponse.ErrorMessage != nil &&
			strings.TrimSpace(
				*engineResponse.ErrorMessage,
			) != "" {
			errorMessage = strings.TrimSpace(
				*engineResponse.ErrorMessage,
			)
		}

		return nil, fmt.Errorf(
			"%w: %s",
			ErrRiskEngineUnavailable,
			errorMessage,
		)
	}

	if engineResponse.Assessment == nil {
		return nil, fmt.Errorf(
			"%w: assessment is missing",
			ErrInvalidRiskEngineResponse,
		)
	}

	if err = validateRiskEngineAssessment(
		engineResponse.Assessment,
	); err != nil {
		return nil, err
	}

	return engineResponse.Assessment, nil
}

func (c *RiskEngineClient) endpointURL(
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

func validateRiskEngineAssessment(
	assessment *RiskEngineAssessment,
) error {
	if assessment == nil {
		return fmt.Errorf(
			"%w: assessment is required",
			ErrInvalidRiskEngineResponse,
		)
	}

	scoreValues := []struct {
		name  string
		value float64
	}{
		{
			name:  "overall_risk_score",
			value: assessment.OverallRiskScore,
		},
		{
			name:  "threat_probability",
			value: assessment.ThreatProbability,
		},
		{
			name:  "integrity_risk_score",
			value: assessment.IntegrityRiskScore,
		},
		{
			name:  "confidentiality_risk_score",
			value: assessment.ConfidentialityRiskScore,
		},
		{
			name:  "availability_risk_score",
			value: assessment.AvailabilityRiskScore,
		},
		{
			name:  "confidence_score",
			value: assessment.ConfidenceScore,
		},
	}

	for _, scoreValue := range scoreValues {
		if !IsValidRiskScore(
			scoreValue.value,
		) {
			return fmt.Errorf(
				"%w: %s must be between 0 and 100",
				ErrInvalidRiskEngineResponse,
				scoreValue.name,
			)
		}
	}

	assessment.RiskLevel = strings.ToUpper(
		strings.TrimSpace(
			assessment.RiskLevel,
		),
	)

	expectedRiskLevel, valid :=
		RiskLevelFromScore(
			assessment.OverallRiskScore,
		)
	if !valid ||
		assessment.RiskLevel !=
			expectedRiskLevel {
		return fmt.Errorf(
			"%w: risk level does not match overall score",
			ErrInvalidRiskEngineResponse,
		)
	}

	assessment.ModelName = strings.TrimSpace(
		assessment.ModelName,
	)

	assessment.ModelVersion = strings.TrimSpace(
		assessment.ModelVersion,
	)

	if assessment.ModelName == "" ||
		assessment.ModelVersion == "" {
		return fmt.Errorf(
			"%w: model name and version are required",
			ErrInvalidRiskEngineResponse,
		)
	}

	assessment.ScoreExplanation =
		strings.TrimSpace(
			assessment.ScoreExplanation,
		)

	assessment.RecommendedAction =
		strings.TrimSpace(
			assessment.RecommendedAction,
		)

	if assessment.ScoreExplanation == "" {
		return fmt.Errorf(
			"%w: score explanation is required",
			ErrInvalidRiskEngineResponse,
		)
	}

	if assessment.RecommendedAction == "" {
		return fmt.Errorf(
			"%w: recommended action is required",
			ErrInvalidRiskEngineResponse,
		)
	}

	for index := range assessment.RiskFactors {
		riskFactor :=
			&assessment.RiskFactors[index]

		riskFactor.Code = strings.TrimSpace(
			riskFactor.Code,
		)

		riskFactor.Name = strings.TrimSpace(
			riskFactor.Name,
		)

		riskFactor.Category = strings.TrimSpace(
			riskFactor.Category,
		)

		riskFactor.Description =
			strings.TrimSpace(
				riskFactor.Description,
			)

		if riskFactor.Code == "" ||
			riskFactor.Name == "" ||
			riskFactor.Category == "" {
			return fmt.Errorf(
				"%w: risk factor %d is incomplete",
				ErrInvalidRiskEngineResponse,
				index,
			)
		}

		if math.IsNaN(riskFactor.Weight) ||
			math.IsInf(riskFactor.Weight, 0) ||
			riskFactor.Weight < 0 ||
			riskFactor.Weight > 1 {
			return fmt.Errorf(
				"%w: risk factor %d weight must be between 0 and 1",
				ErrInvalidRiskEngineResponse,
				index,
			)
		}

		if !IsValidRiskScore(
			riskFactor.Score,
		) {
			return fmt.Errorf(
				"%w: risk factor %d score is invalid",
				ErrInvalidRiskEngineResponse,
				index,
			)
		}

		if !IsValidRiskScore(
			riskFactor.Contribution,
		) {
			return fmt.Errorf(
				"%w: risk factor %d contribution is invalid",
				ErrInvalidRiskEngineResponse,
				index,
			)
		}
	}

	return nil
}
