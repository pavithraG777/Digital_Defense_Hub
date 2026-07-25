package preencryption

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidDetectionQuery = errors.New(
	"invalid pre-encryption detection query",
)

func (s *Service) GetDetection(
	ctx context.Context,
	organizationID uuid.UUID,
	detectionIDValue string,
) (*Detection, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"pre-encryption detection service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	detectionID, err :=
		parseDetectionQueryUUID(
			detectionIDValue,
			"detection ID",
		)
	if err != nil {
		return nil, err
	}

	return s.repository.GetDetection(
		ctx,
		organizationID,
		detectionID,
	)
}

func (s *Service) GetDetectionDetails(
	ctx context.Context,
	organizationID uuid.UUID,
	detectionIDValue string,
) (*DetectionDetailsResponse, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"pre-encryption detection service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	detectionID, err :=
		parseDetectionQueryUUID(
			detectionIDValue,
			"detection ID",
		)
	if err != nil {
		return nil, err
	}

	detection, err := s.repository.GetDetection(
		ctx,
		organizationID,
		detectionID,
	)
	if err != nil {
		return nil, err
	}

	events, err :=
		s.repository.ListDetectionEvents(
			ctx,
			organizationID,
			detectionID,
		)
	if err != nil {
		return nil, err
	}

	if events == nil {
		events = make(
			[]DetectionEventResponse,
			0,
		)
	}

	return &DetectionDetailsResponse{
		Detection: *detection,
		Events:    events,
	}, nil
}

func (s *Service) ListDetections(
	ctx context.Context,
	organizationID uuid.UUID,
	query ListDetectionsQuery,
) (*ListDetectionsResponse, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New(
			"pre-encryption detection service is unavailable",
		)
	}

	if organizationID == uuid.Nil {
		return nil, errors.New(
			"organization ID is required",
		)
	}

	query.RiskLevel =
		NormalizeConstant(
			query.RiskLevel,
		)

	query.Classification =
		NormalizeConstant(
			query.Classification,
		)

	query.DetectionStage =
		NormalizeConstant(
			query.DetectionStage,
		)

	query.DetectionMethod =
		NormalizeConstant(
			query.DetectionMethod,
		)

	query.Status =
		NormalizeConstant(
			query.Status,
		)

	query.ActionStatus =
		NormalizeConstant(
			query.ActionStatus,
		)

	query.DeviceIdentifier =
		strings.TrimSpace(
			query.DeviceIdentifier,
		)

	query.ProcessName =
		strings.TrimSpace(
			query.ProcessName,
		)

	if query.RiskLevel != "" &&
		!IsSupportedRiskLevel(
			query.RiskLevel,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported risk_level",
			ErrInvalidDetectionQuery,
		)
	}

	if query.Classification != "" &&
		!IsSupportedClassification(
			query.Classification,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported classification",
			ErrInvalidDetectionQuery,
		)
	}

	if query.DetectionStage != "" &&
		!IsSupportedDetectionStage(
			query.DetectionStage,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported detection_stage",
			ErrInvalidDetectionQuery,
		)
	}

	if query.DetectionMethod != "" &&
		!IsSupportedDetectionMethod(
			query.DetectionMethod,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported detection_method",
			ErrInvalidDetectionQuery,
		)
	}

	if query.Status != "" &&
		!IsSupportedDetectionStatus(
			query.Status,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported status",
			ErrInvalidDetectionQuery,
		)
	}

	if query.ActionStatus != "" &&
		!IsSupportedActionStatus(
			query.ActionStatus,
		) {
		return nil, fmt.Errorf(
			"%w: unsupported action_status",
			ErrInvalidDetectionQuery,
		)
	}

	detectedFrom, err :=
		parseDetectionQueryTime(
			query.DetectedFrom,
			"detected_from",
		)
	if err != nil {
		return nil, err
	}

	detectedTo, err :=
		parseDetectionQueryTime(
			query.DetectedTo,
			"detected_to",
		)
	if err != nil {
		return nil, err
	}

	if detectedFrom != nil &&
		detectedTo != nil &&
		detectedTo.Before(
			*detectedFrom,
		) {
		return nil, fmt.Errorf(
			"%w: detected_to must not be before detected_from",
			ErrInvalidDetectionQuery,
		)
	}

	page := query.Page
	if page <= 0 {
		page = 1
	}

	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize =
			defaultDetectionPageSize
	}

	if pageSize >
		maximumDetectionPageSize {
		pageSize =
			maximumDetectionPageSize
	}

	detections, total, err :=
		s.repository.ListDetections(
			ctx,
			organizationID,
			DetectionListFilter{
				RiskLevel: query.RiskLevel,

				Classification: query.Classification,

				DetectionStage: query.DetectionStage,

				DetectionMethod: query.DetectionMethod,

				Status: query.Status,

				ActionStatus: query.ActionStatus,

				DeviceIdentifier: query.DeviceIdentifier,

				ProcessName: query.ProcessName,

				RequiresHumanReview: query.RequiresHumanReview,

				DetectedFrom: detectedFrom,
				DetectedTo:   detectedTo,

				Limit: pageSize,

				Offset: (page - 1) *
					pageSize,
			},
		)
	if err != nil {
		return nil, err
	}

	if detections == nil {
		detections = make(
			[]Detection,
			0,
		)
	}

	totalPages := 0

	if total > 0 {
		totalPages = int(
			(total +
				int64(pageSize) -
				1) /
				int64(pageSize),
		)
	}

	return &ListDetectionsResponse{
		Items: detections,

		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func (s *Service) CheckDetectionEngineHealth(
	ctx context.Context,
) (*DetectionEngineHealthResponse, error) {
	if s == nil || s.engine == nil {
		return nil, ErrDetectionEngineUnavailable
	}

	if err := s.engine.CheckHealth(
		ctx,
	); err != nil {
		return nil, err
	}

	return &DetectionEngineHealthResponse{
		Status: "HEALTHY",
	}, nil
}

func parseDetectionQueryUUID(
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
			ErrInvalidDetectionQuery,
			fieldName,
		)
	}

	return parsedValue, nil
}

func parseDetectionQueryTime(
	value string,
	fieldName string,
) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	parsedValue, err := time.Parse(
		time.RFC3339,
		value,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %s must use RFC3339 format",
			ErrInvalidDetectionQuery,
			fieldName,
		)
	}

	parsedValue = parsedValue.UTC()

	return &parsedValue, nil
}
