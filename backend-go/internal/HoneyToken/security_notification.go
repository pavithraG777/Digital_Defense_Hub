package honeytoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const (
	SecurityNotificationEventThreatDetected = "THREAT_DETECTED"

	SecurityNotificationEventIncidentCreated = "INCIDENT_CREATED"
)

// SecurityNotificationEvent contains security information that must be
// forwarded without coupling HoneyToken directly to the notification package.
type SecurityNotificationEvent struct {
	OrganizationID uuid.UUID
	DepartmentID   *uuid.UUID
	ThreatID       *uuid.UUID
	IncidentID     *uuid.UUID

	EventType string
	Category  string
	Title     string
	Message   string
	Severity  string

	PriorityLevel           int
	DeduplicationKey        string
	RequiresAcknowledgement bool
	Payload                 json.RawMessage
}

// SecurityNotificationPublisher allows the Threat and Incident Engines to
// publish alerts without importing the notification package.
type SecurityNotificationPublisher interface {
	PublishSecurityNotification(
		ctx context.Context,
		event SecurityNotificationEvent,
	) error
}

// SecurityNotificationPublisherFunc connects the HoneyToken Engine to the
// Notification Engine through the router composition layer.
type SecurityNotificationPublisherFunc func(
	ctx context.Context,
	event SecurityNotificationEvent,
) error

func (publisher SecurityNotificationPublisherFunc) PublishSecurityNotification(
	ctx context.Context,
	event SecurityNotificationEvent,
) error {
	if publisher == nil {
		return nil
	}

	return publisher(ctx, event)
}

func (w *ThreatWorker) publishSecurityNotification(
	ctx context.Context,
	event SecurityNotificationEvent,
) error {
	if w == nil ||
		w.securityNotificationPublisher == nil {
		return nil
	}

	return w.securityNotificationPublisher.
		PublishSecurityNotification(
			ctx,
			event,
		)
}

func (w *ThreatWorker) publishThreatDetectedNotification(
	ctx context.Context,
	threat *ThreatResponse,
	threatCreated bool,
) error {
	if threat == nil || !threatCreated {
		return nil
	}

	organizationID, err :=
		parseSecurityNotificationUUID(
			threat.OrganizationID,
			"organization ID",
		)
	if err != nil {
		return err
	}

	threatID, err :=
		parseSecurityNotificationUUID(
			threat.ID,
			"threat ID",
		)
	if err != nil {
		return err
	}

	departmentID, err :=
		parseOptionalSecurityNotificationUUID(
			threat.DepartmentID,
			"department ID",
		)
	if err != nil {
		return err
	}

	message := threat.Title

	if threat.Description != nil &&
		strings.TrimSpace(*threat.Description) != "" {
		message = strings.TrimSpace(
			*threat.Description,
		)
	}

	payload, err := json.Marshal(
		map[string]any{
			"threat_id":           threat.ID,
			"threat_code":         threat.ThreatCode,
			"threat_type":         threat.ThreatType,
			"threat_category":     threat.ThreatCategory,
			"detection_method":    threat.DetectionMethod,
			"threat_score":        threat.ThreatScore,
			"confidence_score":    threat.ConfidenceScore,
			"classification":      threat.Classification,
			"status":              threat.Status,
			"event_count":         threat.EventCount,
			"affected_file_count": threat.AffectedFileCount,
			"device_name":         threat.DeviceName,
			"device_identifier":   threat.DeviceIdentifier,
			"first_detected_at":   threat.FirstDetectedAt,
			"last_detected_at":    threat.LastDetectedAt,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"encode threat notification payload: %w",
			err,
		)
	}

	requiresAcknowledgement :=
		threat.Severity == ThreatLevelHigh ||
			threat.Severity == ThreatLevelCritical

	return w.publishSecurityNotification(
		ctx,
		SecurityNotificationEvent{
			OrganizationID: organizationID,
			DepartmentID:   departmentID,
			ThreatID:       &threatID,
			EventType:      SecurityNotificationEventThreatDetected,
			Category:       "SECURITY",
			Title: "Security Threat Detected: " +
				threat.Title,
			Message:       message,
			Severity:      threat.Severity,
			PriorityLevel: 0,
			DeduplicationKey: "THREAT_DETECTED:" +
				threatID.String(),
			RequiresAcknowledgement: requiresAcknowledgement,
			Payload:                 payload,
		},
	)
}

func parseSecurityNotificationUUID(
	value string,
	fieldName string,
) (uuid.UUID, error) {
	parsedValue, err := uuid.Parse(
		strings.TrimSpace(value),
	)
	if err != nil || parsedValue == uuid.Nil {
		return uuid.Nil, fmt.Errorf(
			"invalid security notification %s",
			fieldName,
		)
	}

	return parsedValue, nil
}

func parseOptionalSecurityNotificationUUID(
	value *string,
	fieldName string,
) (*uuid.UUID, error) {
	if value == nil ||
		strings.TrimSpace(*value) == "" {
		return nil, nil
	}

	parsedValue, err :=
		parseSecurityNotificationUUID(
			*value,
			fieldName,
		)
	if err != nil {
		return nil, err
	}

	return &parsedValue, nil
}

func (w *ThreatWorker) publishIncidentCreatedNotification(
	ctx context.Context,
	threat *ThreatResponse,
	incidentIDValue string,
	incidentNumber string,
	incidentCreated bool,
) error {
	if threat == nil || !incidentCreated {
		return nil
	}

	organizationID, err :=
		parseSecurityNotificationUUID(
			threat.OrganizationID,
			"organization ID",
		)
	if err != nil {
		return err
	}

	threatID, err :=
		parseSecurityNotificationUUID(
			threat.ID,
			"threat ID",
		)
	if err != nil {
		return err
	}

	incidentID, err :=
		parseSecurityNotificationUUID(
			incidentIDValue,
			"incident ID",
		)
	if err != nil {
		return err
	}

	departmentID, err :=
		parseOptionalSecurityNotificationUUID(
			threat.DepartmentID,
			"department ID",
		)
	if err != nil {
		return err
	}

	incidentNumber = strings.TrimSpace(
		incidentNumber,
	)
	if incidentNumber == "" {
		return errors.New(
			"incident number is required for notification",
		)
	}

	payload, err := json.Marshal(
		map[string]any{
			"incident_id":       incidentID.String(),
			"incident_number":   incidentNumber,
			"threat_id":         threat.ID,
			"threat_code":       threat.ThreatCode,
			"threat_type":       threat.ThreatType,
			"threat_category":   threat.ThreatCategory,
			"threat_score":      threat.ThreatScore,
			"classification":    threat.Classification,
			"detection_method":  threat.DetectionMethod,
			"device_name":       threat.DeviceName,
			"device_identifier": threat.DeviceIdentifier,
			"automated":         true,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"encode incident notification payload: %w",
			err,
		)
	}

	requiresAcknowledgement :=
		threat.Severity == ThreatLevelHigh ||
			threat.Severity == ThreatLevelCritical

	return w.publishSecurityNotification(
		ctx,
		SecurityNotificationEvent{
			OrganizationID: organizationID,
			DepartmentID:   departmentID,
			ThreatID:       &threatID,
			IncidentID:     &incidentID,
			EventType:      SecurityNotificationEventIncidentCreated,
			Category:       "SECURITY",
			Title: "Security Incident Created: " +
				incidentNumber,
			Message: fmt.Sprintf(
				"Automatic incident %s was created from threat %s.",
				incidentNumber,
				threat.ThreatCode,
			),
			Severity:      threat.Severity,
			PriorityLevel: 0,
			DeduplicationKey: "INCIDENT_CREATED:" +
				incidentID.String(),
			RequiresAcknowledgement: requiresAcknowledgement,
			Payload:                 payload,
		},
	)
}
