package preencryption

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidDetectionWorkflowRequest = errors.New(
	"invalid pre-encryption detection workflow request",
)

func (s *Service) UpdateDetectionStatus(
	ctx context.Context,
	organizationID uuid.UUID,
	userID uuid.UUID,
	detectionIDValue string,
	request UpdateDetectionStatusRequest,
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

	if userID == uuid.Nil {
		return nil, errors.New(
			"user ID is required",
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

	if request.Status == nil &&
		request.ActionStatus == nil &&
		request.ReviewNotes == nil &&
		request.MitigationSummary == nil {
		return nil, ErrNoDetectionWorkflowChanges
	}

	currentDetection, err :=
		s.repository.GetDetection(
			ctx,
			organizationID,
			detectionID,
		)
	if err != nil {
		return nil, err
	}

	status, err :=
		normalizeDetectionWorkflowConstant(
			request.Status,
			"status",
			IsSupportedDetectionStatus,
		)
	if err != nil {
		return nil, err
	}

	actionStatus, err :=
		normalizeDetectionWorkflowConstant(
			request.ActionStatus,
			"action_status",
			IsSupportedActionStatus,
		)
	if err != nil {
		return nil, err
	}

	reviewNotes, err :=
		normalizeDetectionWorkflowText(
			request.ReviewNotes,
			"review_notes",
			4000,
		)
	if err != nil {
		return nil, err
	}

	mitigationSummary, err :=
		normalizeDetectionWorkflowText(
			request.MitigationSummary,
			"mitigation_summary",
			4000,
		)
	if err != nil {
		return nil, err
	}

	finalStatus := currentDetection.Status
	if status != nil {
		finalStatus = *status
	}

	finalActionStatus :=
		currentDetection.ActionStatus
	if actionStatus != nil {
		finalActionStatus =
			*actionStatus
	}

	if finalStatus ==
		DetectionStatusFalsePositive {
		if actionStatus == nil {
			normalizedActionStatus :=
				ActionStatusNotRequired

			actionStatus =
				&normalizedActionStatus

			finalActionStatus =
				normalizedActionStatus
		}

		if finalActionStatus !=
			ActionStatusNotRequired {
			return nil, fmt.Errorf(
				"%w: false-positive detection action status must be NOT_REQUIRED",
				ErrInvalidDetectionWorkflowRequest,
			)
		}
	}

	if status != nil &&
		(*status ==
			DetectionStatusConfirmed ||
			*status ==
				DetectionStatusFalsePositive) &&
		reviewNotes == nil {
		return nil, fmt.Errorf(
			"%w: review_notes is required for status %s",
			ErrInvalidDetectionWorkflowRequest,
			*status,
		)
	}

	if finalStatus ==
		DetectionStatusMitigated {
		if mitigationSummary == nil {
			return nil, fmt.Errorf(
				"%w: mitigation_summary is required for MITIGATED status",
				ErrInvalidDetectionWorkflowRequest,
			)
		}

		if finalActionStatus !=
			ActionStatusCompleted {
			return nil, fmt.Errorf(
				"%w: action_status must be COMPLETED before marking a detection as MITIGATED",
				ErrInvalidDetectionWorkflowRequest,
			)
		}
	}

	if actionStatus != nil &&
		*actionStatus ==
			ActionStatusCompleted &&
		mitigationSummary == nil {
		return nil, fmt.Errorf(
			"%w: mitigation_summary is required when action_status is COMPLETED",
			ErrInvalidDetectionWorkflowRequest,
		)
	}

	if finalStatus ==
		DetectionStatusConfirmed &&
		finalActionStatus ==
			ActionStatusNotRequired {
		return nil, fmt.Errorf(
			"%w: confirmed detection action status cannot be NOT_REQUIRED",
			ErrInvalidDetectionWorkflowRequest,
		)
	}

	return s.repository.UpdateDetectionWorkflow(
		ctx,
		DetectionWorkflowUpdate{
			OrganizationID: organizationID,

			DetectionID: detectionID,

			UpdatedBy: userID,

			Status: status,

			ActionStatus: actionStatus,

			ReviewNotes: reviewNotes,

			MitigationSummary: mitigationSummary,

			UpdatedAt: time.Now().UTC(),
		},
	)
}

func normalizeDetectionWorkflowConstant(
	value *string,
	fieldName string,
	validator func(string) bool,
) (*string, error) {
	if value == nil {
		return nil, nil
	}

	normalizedValue :=
		NormalizeConstant(
			*value,
		)

	if normalizedValue == "" ||
		!validator(normalizedValue) {
		return nil, fmt.Errorf(
			"%w: unsupported %s",
			ErrInvalidDetectionWorkflowRequest,
			fieldName,
		)
	}

	return &normalizedValue, nil
}

func normalizeDetectionWorkflowText(
	value *string,
	fieldName string,
	maximumLength int,
) (*string, error) {
	if value == nil {
		return nil, nil
	}

	normalizedValue :=
		strings.TrimSpace(
			*value,
		)

	if normalizedValue == "" {
		return nil, fmt.Errorf(
			"%w: %s must not be empty",
			ErrInvalidDetectionWorkflowRequest,
			fieldName,
		)
	}

	if len([]rune(normalizedValue)) >
		maximumLength {
		return nil, fmt.Errorf(
			"%w: %s exceeds maximum length of %d characters",
			ErrInvalidDetectionWorkflowRequest,
			fieldName,
			maximumLength,
		)
	}

	return &normalizedValue, nil
}
