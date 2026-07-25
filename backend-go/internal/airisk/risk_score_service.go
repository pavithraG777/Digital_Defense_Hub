package airisk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidRiskScoreRequest = errors.New(
	"invalid AI risk score request",
)

const (
	defaultRiskScoreValidity = 24 * time.Hour
	maximumRiskScoreValidity = 30 * 24 * time.Hour
)

type storedRiskFactorPayload struct {
	SchemaVersion string `json:"schema_version"`
	ModelName     string `json:"model_name"`
	ModelVersion  string `json:"model_version"`

	Factors []RiskFactor `json:"factors"`
}

type Service struct {
	repository      *Repository
	riskEngine      *RiskEngineClient
	defaultValidity time.Duration
}

func NewService(
	repository *Repository,
	riskEngine *RiskEngineClient,
	defaultValidity time.Duration,
) (*Service, error) {
	if repository == nil {
		return nil, errors.New(
			"AI risk repository is required",
		)
	}

	if riskEngine == nil {
		return nil, errors.New(
			"AI Risk Scoring Engine client is required",
		)
	}

	if defaultValidity <= 0 {
		defaultValidity =
			defaultRiskScoreValidity
	}

	if defaultValidity >
		maximumRiskScoreValidity {
		return nil, errors.New(
			"default AI risk score validity exceeds maximum duration",
		)
	}

	return &Service{
		repository:      repository,
		riskEngine:      riskEngine,
		defaultValidity: defaultValidity,
	}, nil
}

func (s *Service) CalculateIncidentRisk(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentIDValue string,
	request CalculateIncidentRiskRequest,
) (*CalculateIncidentRiskResponse, error) {
	if s == nil ||
		s.repository == nil ||
		s.riskEngine == nil {
		return nil, errors.New(
			"AI risk service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	incidentID, err := parseRiskRequiredUUID(
		incidentIDValue,
		"incident ID",
	)
	if err != nil {
		return nil, err
	}

	validity, err := s.resolveValidity(
		request.ValidityHours,
	)
	if err != nil {
		return nil, err
	}

	if err = s.repository.ValidateIncidentSubject(
		ctx,
		organizationID,
		incidentID,
	); err != nil {
		return nil, err
	}

	calculatedAt := time.Now().UTC()

	if !request.ForceRecalculate {
		existingRiskScore, findErr :=
			s.repository.FindActiveRiskScoreBySubject(
				ctx,
				organizationID,
				RiskSubjectTypeIncident,
				incidentID,
				calculatedAt,
			)

		if findErr == nil {
			response, modelName,
				modelVersion, buildErr :=
				buildRiskScoreResponse(
					existingRiskScore,
				)
			if buildErr != nil {
				return nil, buildErr
			}

			return &CalculateIncidentRiskResponse{
				RiskScore:    response,
				Reused:       true,
				ModelName:    modelName,
				ModelVersion: modelVersion,
			}, nil
		}

		if !errors.Is(
			findErr,
			ErrRiskScoreNotFound,
		) {
			return nil, findErr
		}
	}

	features, err :=
		s.repository.LoadIncidentRiskFeatures(
			ctx,
			organizationID,
			incidentID,
		)
	if err != nil {
		return nil, err
	}

	engineRequest := RiskEngineRequest{
		RequestID: uuid.New(),

		RequestType: RiskEngineRequestTypeIncidentRansomware,

		SchemaVersion: RiskFeatureSchemaVersion,

		OrganizationID: organizationID,
		IncidentID:     incidentID,
		Features:       *features,
		RequestedAt:    calculatedAt,
	}

	assessment, err :=
		s.riskEngine.AssessIncidentRisk(
			ctx,
			engineRequest,
		)
	if err != nil {
		return nil, err
	}

	storedRiskFactors, err := json.Marshal(
		storedRiskFactorPayload{
			SchemaVersion: RiskFeatureSchemaVersion,

			ModelName: assessment.ModelName,

			ModelVersion: assessment.ModelVersion,

			Factors: assessment.RiskFactors,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode AI risk factors: %w",
			err,
		)
	}

	expiresAt := calculatedAt.Add(validity)

	threatProbability :=
		assessment.ThreatProbability

	integrityRiskScore :=
		assessment.IntegrityRiskScore

	confidentialityRiskScore :=
		assessment.ConfidentialityRiskScore

	availabilityRiskScore :=
		assessment.AvailabilityRiskScore

	confidenceScore :=
		assessment.ConfidenceScore

	scoreExplanation :=
		assessment.ScoreExplanation

	recommendedAction :=
		assessment.RecommendedAction

	incidentReference := incidentID

	riskScore := &RiskScore{
		ID:             uuid.New(),
		OrganizationID: organizationID,

		IncidentID: &incidentReference,

		RiskSubjectType: RiskSubjectTypeIncident,

		RiskSubjectID: incidentID,

		OverallRiskScore: assessment.OverallRiskScore,

		RiskLevel: assessment.RiskLevel,

		ThreatProbability: &threatProbability,

		IntegrityRiskScore: &integrityRiskScore,

		ConfidentialityRiskScore: &confidentialityRiskScore,

		AvailabilityRiskScore: &availabilityRiskScore,

		ConfidenceScore: &confidenceScore,

		RiskFactors: storedRiskFactors,

		ScoreExplanation: &scoreExplanation,

		RecommendedAction: &recommendedAction,

		RequiresHumanReview: assessment.RequiresHumanReview,

		Status: RiskStatusActive,

		CalculatedAt: calculatedAt,

		ExpiresAt: &expiresAt,
	}

	savedRiskScore, created, err :=
		s.repository.SaveCalculatedRiskScore(
			ctx,
			riskScore,
			request.ForceRecalculate,
		)
	if err != nil {
		return nil, err
	}

	response, modelName,
		modelVersion, err :=
		buildRiskScoreResponse(
			savedRiskScore,
		)
	if err != nil {
		return nil, err
	}

	return &CalculateIncidentRiskResponse{
		RiskScore:    response,
		Reused:       !created,
		ModelName:    modelName,
		ModelVersion: modelVersion,
	}, nil
}

func (s *Service) GetRiskScore(
	ctx context.Context,
	organizationID uuid.UUID,
	riskScoreIDValue string,
) (*RiskScoreResponse, error) {
	if s == nil ||
		s.repository == nil {
		return nil, errors.New(
			"AI risk service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	riskScoreID, err := parseRiskRequiredUUID(
		riskScoreIDValue,
		"AI risk score ID",
	)
	if err != nil {
		return nil, err
	}

	riskScore, err :=
		s.repository.FindRiskScoreByID(
			ctx,
			organizationID,
			riskScoreID,
		)
	if err != nil {
		return nil, err
	}

	response, _, _, err :=
		buildRiskScoreResponse(riskScore)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (s *Service) CheckRiskEngineHealth(
	ctx context.Context,
) error {
	if s == nil ||
		s.riskEngine == nil {
		return ErrRiskEngineUnavailable
	}

	return s.riskEngine.CheckHealth(ctx)
}

func (s *Service) resolveValidity(
	validityHours *int,
) (time.Duration, error) {
	if validityHours == nil {
		return s.defaultValidity, nil
	}

	if *validityHours < 1 ||
		*validityHours > 720 {
		return 0, fmt.Errorf(
			"%w: validity_hours must be between 1 and 720",
			ErrInvalidRiskScoreRequest,
		)
	}

	validity :=
		time.Duration(*validityHours) *
			time.Hour

	if validity >
		maximumRiskScoreValidity {
		return 0, fmt.Errorf(
			"%w: validity duration exceeds maximum",
			ErrInvalidRiskScoreRequest,
		)
	}

	return validity, nil
}

func parseRiskRequiredUUID(
	value string,
	fieldName string,
) (uuid.UUID, error) {
	parsedValue, err := uuid.Parse(
		strings.TrimSpace(value),
	)
	if err != nil ||
		parsedValue == uuid.Nil {
		return uuid.Nil, fmt.Errorf(
			"%w: %s must be a valid UUID",
			ErrInvalidRiskScoreRequest,
			fieldName,
		)
	}

	return parsedValue, nil
}

func buildRiskScoreResponse(
	riskScore *RiskScore,
) (
	RiskScoreResponse,
	string,
	string,
	error,
) {
	if riskScore == nil {
		return RiskScoreResponse{},
			"",
			"",
			errors.New(
				"AI risk score is required",
			)
	}

	riskFactors, modelName,
		modelVersion, err :=
		decodeStoredRiskFactors(
			riskScore.RiskFactors,
		)
	if err != nil {
		return RiskScoreResponse{},
			"",
			"",
			err
	}

	response := RiskScoreResponse{
		ID:             riskScore.ID,
		OrganizationID: riskScore.OrganizationID,

		AnalysisJobID: riskScore.AnalysisJobID,

		IncidentID: riskScore.IncidentID,

		AlertID: riskScore.AlertID,

		EvidenceID: riskScore.EvidenceID,

		RiskSubjectType: riskScore.RiskSubjectType,

		RiskSubjectID: riskScore.RiskSubjectID,

		OverallRiskScore: riskScore.OverallRiskScore,

		RiskLevel: riskScore.RiskLevel,

		ThreatProbability: riskScore.ThreatProbability,

		IntegrityRiskScore: riskScore.IntegrityRiskScore,

		ConfidentialityRiskScore: riskScore.ConfidentialityRiskScore,

		AvailabilityRiskScore: riskScore.AvailabilityRiskScore,

		ConfidenceScore: riskScore.ConfidenceScore,

		RiskFactors: riskFactors,

		ScoreExplanation: riskScore.ScoreExplanation,

		RecommendedAction: riskScore.RecommendedAction,

		RequiresHumanReview: riskScore.RequiresHumanReview,

		Status: riskScore.Status,

		CalculatedAt: riskScore.CalculatedAt,

		ExpiresAt: riskScore.ExpiresAt,

		CreatedAt: riskScore.CreatedAt,
	}

	return response,
		modelName,
		modelVersion,
		nil
}

func decodeStoredRiskFactors(
	rawValue json.RawMessage,
) (
	[]RiskFactor,
	string,
	string,
	error,
) {
	trimmedValue := bytes.TrimSpace(
		rawValue,
	)

	if len(trimmedValue) == 0 ||
		bytes.Equal(
			trimmedValue,
			[]byte("null"),
		) {
		return []RiskFactor{},
			"",
			"",
			nil
	}

	if trimmedValue[0] == '[' {
		var legacyFactors []RiskFactor

		if err := json.Unmarshal(
			trimmedValue,
			&legacyFactors,
		); err != nil {
			return nil, "", "", fmt.Errorf(
				"decode legacy AI risk factors: %w",
				err,
			)
		}

		if legacyFactors == nil {
			legacyFactors = []RiskFactor{}
		}

		return legacyFactors,
			"",
			"",
			nil
	}

	var payload storedRiskFactorPayload

	if err := json.Unmarshal(
		trimmedValue,
		&payload,
	); err != nil {
		return nil, "", "", fmt.Errorf(
			"decode AI risk factor payload: %w",
			err,
		)
	}

	if payload.Factors == nil {
		payload.Factors = []RiskFactor{}
	}

	return payload.Factors,
		strings.TrimSpace(
			payload.ModelName,
		),
		strings.TrimSpace(
			payload.ModelVersion,
		),
		nil
}
