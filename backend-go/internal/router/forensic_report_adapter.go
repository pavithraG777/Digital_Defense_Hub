package router

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/HoneyToken"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/dfir"
)

type forensicReportGenerator struct {
	service *dfir.Service
}

func (g forensicReportGenerator) GenerateForensicReport(
	ctx context.Context,
	incident *honeytoken.IncidentResponse,
	threat *honeytoken.ThreatResponse,
) error {
	if g.service == nil || incident == nil || threat == nil {
		return errors.New("forensic report generator is unavailable")
	}

	incidentID, err := uuid.Parse(incident.ID)
	if err != nil {
		return err
	}

	return g.service.GenerateForensicReport(
		ctx,
		incidentID,
		incident.IncidentTitle,
		incident.Severity,
		forensicReportSummary(incident, threat),
	)
}

func forensicReportSummary(
	incident *honeytoken.IncidentResponse,
	threat *honeytoken.ThreatResponse,
) string {
	return "Automatically generated forensic report for " +
		incident.IncidentTitle +
		" after " + threat.ThreatType +
		" (" + threat.ThreatCode + ") was detected."
}
