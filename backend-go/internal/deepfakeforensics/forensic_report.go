package deepfakeforensics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrForensicReportNotFound = errors.New("media forensic report not found")

type MediaForensicReport struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID uuid.UUID      `json:"organization_id"`
	MediaAssetID   uuid.UUID      `json:"media_asset_id"`
	IncidentID     *uuid.UUID     `json:"incident_id,omitempty"`
	ReportNumber   string         `json:"report_number"`
	Status         string         `json:"status"`
	ReportData     map[string]any `json:"report_data"`
	DocumentSHA256 string         `json:"document_sha256"`
	GeneratedBy    uuid.UUID      `json:"generated_by"`
	GeneratedAt    time.Time      `json:"generated_at"`
	ApprovedBy     *uuid.UUID     `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time     `json:"approved_at,omitempty"`
	ApprovalNote   *string        `json:"approval_note,omitempty"`
}

type ApproveMediaForensicReportRequest struct {
	ApprovalNote string `json:"approval_note"`
}

type ForensicReportService struct{ repository *Repository }

func NewForensicReportService(repository *Repository) (*ForensicReportService, error) {
	if repository == nil || !repository.IsAvailable() {
		return nil, ErrRepositoryUnavailable
	}
	return &ForensicReportService{repository: repository}, nil
}

func (s *ForensicReportService) Create(ctx context.Context, organizationID, assetID, userID uuid.UUID) (*MediaForensicReport, error) {
	if s == nil || s.repository == nil || ctx == nil || organizationID == uuid.Nil || assetID == uuid.Nil || userID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	asset, err := s.repository.GetMediaAsset(ctx, organizationID, assetID)
	if err != nil {
		return nil, err
	}
	trust, err := s.repository.GetMediaTrustAssessment(ctx, organizationID, assetID)
	if err != nil && !errors.Is(err, ErrMediaTrustAssessmentNotFound) {
		return nil, err
	}
	data := map[string]any{"report_type": "DEEPFAKE_FORENSIC", "asset": asset, "generated_at": time.Now().UTC()}
	if trust != nil {
		data["trust_assessment"] = trust
	}
	rows, err := s.repository.databasePool.Query(ctx, `SELECT id FROM ai_analysis_jobs WHERE organization_id=$1 AND media_asset_id=$2 AND status='COMPLETED' ORDER BY completed_at DESC NULLS LAST LIMIT 20`, organizationID, assetID)
	if err != nil {
		return nil, fmt.Errorf("list completed media report jobs: %w", err)
	}
	defer rows.Close()
	results := make([]*AnalysisResultBundle, 0)
	for rows.Next() {
		var jobID uuid.UUID
		if err = rows.Scan(&jobID); err != nil {
			return nil, err
		}
		result, resultErr := s.repository.GetAnalysisResult(ctx, organizationID, jobID)
		if resultErr == nil {
			results = append(results, result)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	data["analysis_results"] = results
	pdf := renderForensicReportPDF(asset, trust, results)
	digest := sha256.Sum256(pdf)
	hash := hex.EncodeToString(digest[:])
	reportID := uuid.New()
	now := time.Now().UTC()
	number := fmt.Sprintf("DFR-%s-%s", now.Format("20060102"), strings.ToUpper(strings.ReplaceAll(reportID.String(), "-", "")[:8]))
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	row := s.repository.databasePool.QueryRow(ctx, `INSERT INTO media_forensic_reports (id,organization_id,media_asset_id,incident_id,report_number,report_data,document_pdf,document_sha256,generated_by,generated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (organization_id,media_asset_id) DO UPDATE SET report_data=EXCLUDED.report_data, document_pdf=EXCLUDED.document_pdf, document_sha256=EXCLUDED.document_sha256, generated_by=EXCLUDED.generated_by, generated_at=EXCLUDED.generated_at, status='GENERATED', approved_by=NULL, approved_at=NULL, approval_note=NULL, updated_at=CURRENT_TIMESTAMP RETURNING id,organization_id,media_asset_id,incident_id,report_number,status,report_data,document_sha256,generated_by,generated_at,approved_by,approved_at,approval_note`, reportID, organizationID, assetID, asset.IncidentID, number, jsonData, pdf, hash, userID, now)
	return scanForensicReport(row)
}

func (s *ForensicReportService) Get(ctx context.Context, organizationID, reportID uuid.UUID) (*MediaForensicReport, error) {
	if s == nil || ctx == nil {
		return nil, ErrInvalidRepositoryInput
	}
	row := s.repository.databasePool.QueryRow(ctx, `SELECT id,organization_id,media_asset_id,incident_id,report_number,status,report_data,document_sha256,generated_by,generated_at,approved_by,approved_at,approval_note FROM media_forensic_reports WHERE organization_id=$1 AND id=$2`, organizationID, reportID)
	return scanForensicReport(row)
}
func (s *ForensicReportService) Approve(ctx context.Context, organizationID, reportID, userID uuid.UUID, note string) (*MediaForensicReport, error) {
	if s == nil || ctx == nil || userID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	row := s.repository.databasePool.QueryRow(ctx, `UPDATE media_forensic_reports SET status='APPROVED',approved_by=$3,approved_at=CURRENT_TIMESTAMP,approval_note=$4,updated_at=CURRENT_TIMESTAMP WHERE organization_id=$1 AND id=$2 RETURNING id,organization_id,media_asset_id,incident_id,report_number,status,report_data,document_sha256,generated_by,generated_at,approved_by,approved_at,approval_note`, organizationID, reportID, userID, strings.TrimSpace(note))
	return scanForensicReport(row)
}
func (s *ForensicReportService) PDF(ctx context.Context, organizationID, reportID uuid.UUID) ([]byte, string, error) {
	if s == nil || ctx == nil {
		return nil, "", ErrInvalidRepositoryInput
	}
	var pdf []byte
	var number string
	err := s.repository.databasePool.QueryRow(ctx, `SELECT document_pdf,report_number FROM media_forensic_reports WHERE organization_id=$1 AND id=$2`, organizationID, reportID).Scan(&pdf, &number)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, "", ErrForensicReportNotFound
		}
		return nil, "", err
	}
	return pdf, number, nil
}

type forensicReportScanner interface{ Scan(...any) error }

func scanForensicReport(row forensicReportScanner) (*MediaForensicReport, error) {
	report := &MediaForensicReport{}
	var data []byte
	err := row.Scan(&report.ID, &report.OrganizationID, &report.MediaAssetID, &report.IncidentID, &report.ReportNumber, &report.Status, &data, &report.DocumentSHA256, &report.GeneratedBy, &report.GeneratedAt, &report.ApprovedBy, &report.ApprovedAt, &report.ApprovalNote)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, ErrForensicReportNotFound
		}
		return nil, err
	}
	if err = json.Unmarshal(data, &report.ReportData); err != nil {
		return nil, err
	}
	return report, nil
}

func renderForensicReportPDF(asset *MediaAnalysisAsset, trust *MediaTrustAssessment, results []*AnalysisResultBundle) []byte {
	lines := []string{"DEEPFAKE AND SYNTHETIC MEDIA FORENSIC ANALYSIS", "", "File: " + asset.OriginalFileName, "SHA-256: " + asset.FileHash, "Media type: " + asset.MediaType, ""}
	if trust != nil {
		lines = append(lines, "Verdict: "+trust.Verdict, fmt.Sprintf("Trust score: %.2f", trust.TrustScore), fmt.Sprintf("Risk score: %.2f", trust.RiskScore), fmt.Sprintf("Confidence: %.2f", trust.ConfidenceScore), "")
	}
	lines = append(lines, fmt.Sprintf("Completed analysis results: %d", len(results)), "This report is AI-assisted and requires analyst approval.")
	var content bytes.Buffer
	// T* advances by the active leading. Set it explicitly so each report
	// field has its own readable line instead of overlapping at the top.
	content.WriteString("BT /F1 10 Tf 14 TL 48 744 Td ")
	for index, line := range lines {
		if index > 0 {
			content.WriteString(" T* ")
		}
		fmt.Fprintf(&content, "(%s) Tj", escapePDFText(line))
	}
	content.WriteString(" ET")
	objects := []string{
		"<</Type/Catalog/Pages 2 0 R>>",
		"<</Type/Pages/Count 1/Kids[3 0 R]>>",
		"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>",
		"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
		fmt.Sprintf("<</Length %d>>\nstream\n%s\nendstream", content.Len(), content.String()),
	}
	var document bytes.Buffer
	document.WriteString("%PDF-1.4\n")
	offsets := make([]int, 0, len(objects))
	for index, object := range objects {
		offsets = append(offsets, document.Len())
		fmt.Fprintf(&document, "%d 0 obj\n%s\nendobj\n", index+1, object)
	}
	xrefOffset := document.Len()
	fmt.Fprintf(&document, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&document, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&document, "trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefOffset)
	return document.Bytes()
}

func escapePDFText(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "(", "\\(")
	value = strings.ReplaceAll(value, ")", "\\)")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}
