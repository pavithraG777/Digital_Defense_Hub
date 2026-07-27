package deepfakeforensics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type TrustService struct {
	repository *Repository
}

func NewTrustService(
	repository *Repository,
) (*TrustService, error) {
	if repository == nil ||
		!repository.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}

	return &TrustService{
		repository: repository,
	}, nil
}

func (s *TrustService) GetMediaTrustAssessment(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
) (*MediaTrustAssessment, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		mediaAssetID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	return s.repository.GetMediaTrustAssessment(
		ctx,
		organizationID,
		mediaAssetID,
	)
}

func (s *TrustService) RecalculateMediaTrustAssessment(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
) (*MediaTrustAssessment, error) {
	if !s.isAvailable() ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		mediaAssetID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}

	return s.repository.RecalculateMediaTrustAssessment(
		ctx,
		organizationID,
		mediaAssetID,
	)
}

func (s *TrustService) isAvailable() bool {
	return s != nil &&
		s.repository != nil &&
		s.repository.IsAvailable()
}

func (w *AnalysisWorker) SetMediaTrustEscalationPublisher(
	publisher MediaTrustEscalationPublisher,
) {
	if w == nil {
		return
	}

	w.mu.Lock()
	w.trustEscalationPublisher = publisher
	w.mu.Unlock()
}

func (w *AnalysisWorker) updateTrustAndEscalate(
	parent context.Context,
	source AnalysisSource,
) {
	if w == nil ||
		w.repository == nil ||
		source.Job.OrganizationID == uuid.Nil ||
		source.Asset.ID == uuid.Nil {
		return
	}

	ctx, cancel := context.WithTimeout(
		parent,
		30*time.Second,
	)
	defer cancel()

	assessment, err :=
		w.repository.RecalculateMediaTrustAssessment(
			ctx,
			source.Job.OrganizationID,
			source.Asset.ID,
		)
	if errors.Is(
		err,
		ErrInsufficientMediaTrustEvidence,
	) {
		return
	}
	if err != nil {
		w.logger.Error(
			"Failed to update media trust assessment",
			zap.String(
				"organization_id",
				source.Job.OrganizationID.String(),
			),
			zap.String(
				"media_asset_id",
				source.Asset.ID.String(),
			),
			zap.Error(err),
		)
		return
	}
	if !assessment.RequiresEscalation() {
		return
	}

	w.mu.RLock()
	publisher := w.trustEscalationPublisher
	w.mu.RUnlock()
	if publisher == nil {
		return
	}

	claimed, err :=
		w.repository.ClaimMediaTrustEscalation(
			ctx,
			assessment.ID,
		)
	if errors.Is(err, ErrAnalysisJobConflict) {
		return
	}
	if err != nil {
		w.logger.Error(
			"Failed to claim media trust escalation",
			zap.String(
				"media_trust_assessment_id",
				assessment.ID.String(),
			),
			zap.Error(err),
		)
		return
	}

	actorUserID := uuid.Nil
	if source.Job.RequestedBy != nil {
		actorUserID = *source.Job.RequestedBy
	}
	if actorUserID == uuid.Nil {
		cause := errors.New(
			"requesting user is unavailable for incident escalation",
		)
		_ = w.repository.FailMediaTrustEscalation(
			ctx,
			claimed.ID,
			cause,
		)
		return
	}

	result, publishErr :=
		publisher.PublishMediaTrustEscalation(
			ctx,
			MediaTrustEscalationEvent{
				Assessment:  *claimed,
				Asset:       source.Asset,
				ActorUserID: actorUserID,
			},
		)
	if publishErr != nil &&
		(result == nil ||
			result.IncidentID == uuid.Nil ||
			result.IncidentEvidenceID == uuid.Nil) {
		_ = w.repository.FailMediaTrustEscalation(
			ctx,
			claimed.ID,
			publishErr,
		)
		w.logger.Error(
			"Media trust escalation failed",
			zap.String(
				"media_trust_assessment_id",
				claimed.ID.String(),
			),
			zap.Error(publishErr),
		)
		return
	}
	if result == nil {
		publishErr = fmt.Errorf(
			"media trust escalation publisher returned no result",
		)
		_ = w.repository.FailMediaTrustEscalation(
			ctx,
			claimed.ID,
			publishErr,
		)
		return
	}

	if err = w.repository.CompleteMediaTrustEscalation(
		ctx,
		claimed.ID,
		*result,
	); err != nil {
		w.logger.Error(
			"Failed to complete media trust escalation",
			zap.String(
				"media_trust_assessment_id",
				claimed.ID.String(),
			),
			zap.Error(err),
		)
		return
	}

	if publishErr != nil {
		w.logger.Error(
			"Media incident created but notification delivery failed",
			zap.String(
				"media_trust_assessment_id",
				claimed.ID.String(),
			),
			zap.String(
				"incident_id",
				result.IncidentID.String(),
			),
			zap.Error(publishErr),
		)
	}

	w.logger.Warn(
		"High-risk media automatically escalated",
		zap.String(
			"organization_id",
			claimed.OrganizationID.String(),
		),
		zap.String(
			"media_asset_id",
			claimed.MediaAssetID.String(),
		),
		zap.String(
			"incident_id",
			result.IncidentID.String(),
		),
		zap.String(
			"risk_level",
			claimed.RiskLevel,
		),
		zap.Float64(
			"risk_score",
			claimed.RiskScore,
		),
	)
}
