package airisk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (s *Service) ListRiskScores(
	ctx context.Context,
	organizationID uuid.UUID,
	request ListRiskScoresRequest,
) (*ListRiskScoresResponse, error) {
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

	riskSubjectType := strings.ToUpper(
		strings.TrimSpace(
			request.RiskSubjectType,
		),
	)

	riskLevel := strings.ToUpper(
		strings.TrimSpace(
			request.RiskLevel,
		),
	)

	status := strings.ToUpper(
		strings.TrimSpace(
			request.Status,
		),
	)

	if riskSubjectType != "" &&
		!IsSupportedRiskSubjectType(
			riskSubjectType,
		) {
		return nil, fmt.Errorf(
			"%w: risk_subject_type is invalid",
			ErrInvalidRiskScoreRequest,
		)
	}

	if riskLevel != "" &&
		!IsSupportedRiskLevel(
			riskLevel,
		) {
		return nil, fmt.Errorf(
			"%w: risk_level is invalid",
			ErrInvalidRiskScoreRequest,
		)
	}

	if status != "" &&
		!IsSupportedRiskStatus(
			status,
		) {
		return nil, fmt.Errorf(
			"%w: status is invalid",
			ErrInvalidRiskScoreRequest,
		)
	}

	var riskSubjectID *uuid.UUID

	riskSubjectIDValue := strings.TrimSpace(
		request.RiskSubjectID,
	)

	if riskSubjectIDValue != "" {
		if riskSubjectType == "" {
			return nil, fmt.Errorf(
				"%w: risk_subject_type is required when risk_subject_id is provided",
				ErrInvalidRiskScoreRequest,
			)
		}

		parsedRiskSubjectID, err :=
			parseRiskRequiredUUID(
				riskSubjectIDValue,
				"risk subject ID",
			)
		if err != nil {
			return nil, err
		}

		riskSubjectID =
			&parsedRiskSubjectID
	}

	page := request.Page
	if page <= 0 {
		page = 1
	}

	pageSize := request.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}

	if pageSize > 100 {
		pageSize = 100
	}

	riskScores, total, err :=
		s.repository.ListRiskScores(
			ctx,
			RiskScoreListFilter{
				OrganizationID: organizationID,

				RiskSubjectType: riskSubjectType,

				RiskSubjectID: riskSubjectID,

				RiskLevel: riskLevel,

				Status: status,

				Limit: pageSize,

				Offset: (page - 1) *
					pageSize,
			},
		)
	if err != nil {
		return nil, err
	}

	items := make(
		[]RiskScoreResponse,
		0,
		len(riskScores),
	)

	for index := range riskScores {
		response, _, _, buildErr :=
			buildRiskScoreResponse(
				&riskScores[index],
			)
		if buildErr != nil {
			return nil, buildErr
		}

		items = append(
			items,
			response,
		)
	}

	totalPages := 0

	if total > 0 {
		totalPages = int(
			(total + int64(pageSize) - 1) /
				int64(pageSize),
		)
	}

	return &ListRiskScoresResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func (s *Service) GetActiveIncidentRiskScore(
	ctx context.Context,
	organizationID uuid.UUID,
	incidentIDValue string,
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

	incidentID, err := parseRiskRequiredUUID(
		incidentIDValue,
		"incident ID",
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

	riskScore, err :=
		s.repository.FindActiveRiskScoreBySubject(
			ctx,
			organizationID,
			RiskSubjectTypeIncident,
			incidentID,
			time.Now().UTC(),
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
