package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	honeytoken "github.com/pavithraG777/cyber-security-platform/backend/internal/HoneyToken"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/deepfakeforensics"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/notification"
)

type mediaTrustEscalationPublisher struct {
	incidentService     *honeytoken.IncidentService
	notificationService *notification.SecurityNotificationService
}

func newMediaTrustEscalationPublisher(
	incidentService *honeytoken.IncidentService,
	notificationService *notification.SecurityNotificationService,
) (
	deepfakeforensics.MediaTrustEscalationPublisher,
	error,
) {
	if incidentService == nil {
		return nil, errors.New(
			"incident service is required for media trust escalation",
		)
	}
	if notificationService == nil {
		return nil, errors.New(
			"notification service is required for media trust escalation",
		)
	}

	return &mediaTrustEscalationPublisher{
		incidentService:     incidentService,
		notificationService: notificationService,
	}, nil
}

func (publisher *mediaTrustEscalationPublisher) PublishMediaTrustEscalation(
	ctx context.Context,
	event deepfakeforensics.MediaTrustEscalationEvent,
) (*deepfakeforensics.MediaTrustEscalationResult, error) {
	if publisher == nil ||
		publisher.incidentService == nil ||
		publisher.notificationService == nil {
		return nil, errors.New(
			"media trust escalation publisher is unavailable",
		)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if event.Assessment.ID == uuid.Nil ||
		event.Assessment.OrganizationID == uuid.Nil ||
		event.Asset.ID == uuid.Nil ||
		event.ActorUserID == uuid.Nil {
		return nil, errors.New(
			"invalid media trust escalation event",
		)
	}

	description := fmt.Sprintf(
		"Offline media analysis classified %s as %s. "+
			"Trust score %.2f, risk score %.2f and confidence %.2f.",
		event.Asset.OriginalFileName,
		event.Assessment.Verdict,
		event.Assessment.TrustScore,
		event.Assessment.RiskScore,
		event.Assessment.ConfidenceScore,
	)
	initialFindings := mediaTrustInitialFindings(event)
	detectedAt := event.Assessment.EvaluatedAt.UTC().
		Format(time.RFC3339Nano)

	var departmentID *string
	if event.Asset.DepartmentID != nil {
		value := event.Asset.DepartmentID.String()
		departmentID = &value
	}

	incident, err := publisher.incidentService.CreateIncident(
		ctx,
		event.Assessment.OrganizationID,
		event.ActorUserID,
		honeytoken.CreateIncidentRequest{
			DepartmentID: departmentID,
			IncidentTitle: "Suspicious media detected: " +
				event.Asset.OriginalFileName,
			Description:      &description,
			IncidentCategory: honeytoken.IncidentCategoryDeepfake,
			Severity: mediaTrustIncidentSeverity(
				event.Assessment.RiskLevel,
			),
			Priority: mediaTrustIncidentPriority(
				event.Assessment.RiskLevel,
			),
			DetectionSource:   honeytoken.IncidentDetectionSourceAIAnalysis,
			EvidencePreserved: true,
			InitialFindings:   &initialFindings,
			DetectedAt:        &detectedAt,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create media forensics incident: %w",
			err,
		)
	}

	metadata, err := json.Marshal(
		map[string]any{
			"media_asset_id":            event.Asset.ID,
			"media_trust_assessment_id": event.Assessment.ID,
			"verdict":                   event.Assessment.Verdict,
			"classification":            event.Assessment.Classification,
			"risk_level":                event.Assessment.RiskLevel,
			"trust_score":               event.Assessment.TrustScore,
			"risk_score":                event.Assessment.RiskScore,
			"confidence_score":          event.Assessment.ConfidenceScore,
			"trained_model_used":        event.Assessment.TrainedModelUsed,
			"component_scores":          event.Assessment.ComponentScores,
			"signals":                   event.Assessment.Signals,
			"warnings":                  event.Assessment.Warnings,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode media incident evidence metadata: %w",
			err,
		)
	}

	originalFileName := event.Asset.OriginalFileName
	mimeType := event.Asset.MimeType
	fileSize := event.Asset.FileSizeBytes
	fileHash := event.Asset.FileHash
	collectedAt := event.Asset.UploadedAt.UTC().
		Format(time.RFC3339Nano)

	evidence, err :=
		publisher.incidentService.AddIncidentEvidence(
			ctx,
			event.Assessment.OrganizationID,
			incident.ID,
			event.ActorUserID,
			honeytoken.AddIncidentEvidenceRequest{
				EvidenceType: honeytoken.IncidentEvidenceTypeMedia,
				EvidenceName: "Analyzed media: " +
					event.Asset.OriginalFileName,
				Description:      &description,
				OriginalFileName: &originalFileName,
				MimeType:         &mimeType,
				FileSizeBytes:    &fileSize,
				EvidenceHash:     &fileHash,
				HashAlgorithm:    event.Asset.HashAlgorithm,
				CollectedAt:      &collectedAt,
				Metadata:         metadata,
			},
		)
	if err != nil {
		return nil, fmt.Errorf(
			"register media incident evidence: %w",
			err,
		)
	}

	incidentID, err := uuid.Parse(incident.ID)
	if err != nil {
		return nil, fmt.Errorf(
			"parse created media incident ID: %w",
			err,
		)
	}
	evidenceID, err := uuid.Parse(evidence.ID)
	if err != nil {
		return nil, fmt.Errorf(
			"parse created media evidence ID: %w",
			err,
		)
	}

	result := &deepfakeforensics.MediaTrustEscalationResult{
		IncidentID:         incidentID,
		IncidentEvidenceID: evidenceID,
	}

	payload, err := json.Marshal(
		map[string]any{
			"incident_id":               incident.ID,
			"incident_number":           incident.IncidentNumber,
			"incident_evidence_id":      evidence.ID,
			"media_asset_id":            event.Asset.ID,
			"media_trust_assessment_id": event.Assessment.ID,
			"verdict":                   event.Assessment.Verdict,
			"risk_level":                event.Assessment.RiskLevel,
			"risk_score":                event.Assessment.RiskScore,
			"confidence_score":          event.Assessment.ConfidenceScore,
			"automated":                 true,
		},
	)
	if err != nil {
		return result, fmt.Errorf(
			"encode media trust notification payload: %w",
			err,
		)
	}

	err = publisher.notificationService.PublishSecurityAlert(
		ctx,
		notification.SecurityAlertInput{
			OrganizationID:   event.Assessment.OrganizationID,
			DepartmentID:     event.Asset.DepartmentID,
			IncidentID:       &incidentID,
			NotificationType: "INCIDENT_CREATED",
			Category:         "SECURITY",
			Title: "Deepfake/media incident created: " +
				incident.IncidentNumber,
			Message: description,
			Severity: mediaTrustIncidentSeverity(
				event.Assessment.RiskLevel,
			),
			DeduplicationKey: "MEDIA_TRUST_ESCALATION:" +
				event.Assessment.ID.String(),
			RequiresAcknowledgement: true,
			Payload:                 payload,
		},
	)
	if err != nil {
		return result, fmt.Errorf(
			"publish media trust notification: %w",
			err,
		)
	}

	notificationSentAt := time.Now().UTC()
	result.NotificationSentAt = &notificationSentAt
	return result, nil
}

func mediaTrustInitialFindings(
	event deepfakeforensics.MediaTrustEscalationEvent,
) string {
	lines := []string{
		fmt.Sprintf(
			"Combined verdict: %s",
			event.Assessment.Verdict,
		),
		fmt.Sprintf(
			"Risk level: %s (%.2f/100)",
			event.Assessment.RiskLevel,
			event.Assessment.RiskScore,
		),
		fmt.Sprintf(
			"Trust score: %.2f/100",
			event.Assessment.TrustScore,
		),
		fmt.Sprintf(
			"Confidence: %.2f/100",
			event.Assessment.ConfidenceScore,
		),
		fmt.Sprintf(
			"Verified trained model used: %t",
			event.Assessment.TrainedModelUsed,
		),
	}

	for _, warning := range event.Assessment.Warnings {
		warning = strings.TrimSpace(warning)
		if warning != "" {
			lines = append(
				lines,
				"Warning: "+warning,
			)
		}
	}

	return strings.Join(lines, "\n")
}

func mediaTrustIncidentSeverity(
	riskLevel string,
) string {
	if deepfakeforensics.NormalizeConstant(riskLevel) ==
		deepfakeforensics.TrustRiskCritical {
		return "CRITICAL"
	}

	return "HIGH"
}

func mediaTrustIncidentPriority(
	riskLevel string,
) string {
	if deepfakeforensics.NormalizeConstant(riskLevel) ==
		deepfakeforensics.TrustRiskCritical {
		return "URGENT"
	}

	return "HIGH"
}
