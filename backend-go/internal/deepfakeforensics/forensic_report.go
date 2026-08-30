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
	"golang.org/x/crypto/bcrypt"
)

var ErrForensicReportNotFound = errors.New("media forensic report not found")
var ErrForensicReportPasswordRequired = errors.New("forensic report access password required")
var ErrForensicReportPasswordInvalid = errors.New("forensic report access password invalid")

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

type SetForensicReportAccessPasswordRequest struct {
	AccessPassword string `json:"access_password" binding:"required,min=12,max=128"`
}

type ForensicReportPDFRequest struct {
	AccessPassword string `json:"access_password" binding:"max=128"`
}

type forensicReportApproval struct {
	AnalystID  uuid.UUID
	ApprovedAt time.Time
	Note       string
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
	pdf := renderForensicReportPDF(asset, trust, results, nil)
	digest := sha256.Sum256(pdf)
	hash := hex.EncodeToString(digest[:])
	reportID := uuid.New()
	now := time.Now().UTC()
	number := fmt.Sprintf("DFR-%s-%s", now.Format("20060102"), strings.ToUpper(strings.ReplaceAll(reportID.String(), "-", "")[:8]))
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	// A report is an evidence snapshot. Never replace an existing report for an
	// asset, otherwise a later analysis could silently alter preserved evidence.
	row := s.repository.databasePool.QueryRow(ctx, `INSERT INTO media_forensic_reports (id,organization_id,media_asset_id,incident_id,report_number,report_data,document_pdf,document_sha256,generated_by,generated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (organization_id,media_asset_id) DO NOTHING RETURNING id,organization_id,media_asset_id,incident_id,report_number,status,report_data,document_sha256,generated_by,generated_at,approved_by,approved_at,approval_note`, reportID, organizationID, assetID, asset.IncidentID, number, jsonData, pdf, hash, userID, now)
	report, scanErr := scanForensicReport(row)
	if scanErr == nil {
		return report, nil
	}
	if !errors.Is(scanErr, ErrForensicReportNotFound) {
		return nil, scanErr
	}
	return s.repositoryForensicReport(ctx, organizationID, assetID)
}

func (s *ForensicReportService) repositoryForensicReport(ctx context.Context, organizationID, assetID uuid.UUID) (*MediaForensicReport, error) {
	row := s.repository.databasePool.QueryRow(ctx, `SELECT id,organization_id,media_asset_id,incident_id,report_number,status,report_data,document_sha256,generated_by,generated_at,approved_by,approved_at,approval_note FROM media_forensic_reports WHERE organization_id=$1 AND media_asset_id=$2`, organizationID, assetID)
	return scanForensicReport(row)
}

func (s *ForensicReportService) Get(ctx context.Context, organizationID, reportID uuid.UUID) (*MediaForensicReport, error) {
	if s == nil || ctx == nil {
		return nil, ErrInvalidRepositoryInput
	}
	row := s.repository.databasePool.QueryRow(ctx, `SELECT id,organization_id,media_asset_id,incident_id,report_number,status,report_data,document_sha256,generated_by,generated_at,approved_by,approved_at,approval_note FROM media_forensic_reports WHERE organization_id=$1 AND id=$2`, organizationID, reportID)
	return scanForensicReport(row)
}

// List returns report metadata only for the requesting organization. This is
// deliberately organization-scoped so a report index cannot disclose another
// tenant's evidence identifiers or findings.
func (s *ForensicReportService) List(ctx context.Context, organizationID uuid.UUID, page, pageSize int) (*MediaForensicReportListResponse, error) {
	if s == nil || s.repository == nil || ctx == nil || organizationID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	var total int64
	if err := s.repository.databasePool.QueryRow(ctx, `SELECT COUNT(*) FROM media_forensic_reports WHERE organization_id=$1`, organizationID).Scan(&total); err != nil {
		return nil, fmt.Errorf("count media forensic reports: %w", err)
	}
	rows, err := s.repository.databasePool.Query(ctx, `SELECT id,organization_id,media_asset_id,incident_id,report_number,status,report_data,document_sha256,generated_by,generated_at,approved_by,approved_at,approval_note FROM media_forensic_reports WHERE organization_id=$1 ORDER BY generated_at DESC LIMIT $2 OFFSET $3`, organizationID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, fmt.Errorf("list media forensic reports: %w", err)
	}
	defer rows.Close()
	items := make([]MediaForensicReportSummary, 0)
	for rows.Next() {
		report, scanErr := scanForensicReport(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, MediaForensicReportSummary{ID: report.ID, MediaAssetID: report.MediaAssetID, IncidentID: report.IncidentID, ReportNumber: report.ReportNumber, Status: report.Status, DocumentSHA256: report.DocumentSHA256, GeneratedAt: report.GeneratedAt, ApprovedAt: report.ApprovedAt})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	return &MediaForensicReportListResponse{Items: items, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages}, nil
}
func (s *ForensicReportService) Approve(ctx context.Context, organizationID, reportID, userID uuid.UUID, note string) (*MediaForensicReport, error) {
	if s == nil || ctx == nil || userID == uuid.Nil {
		return nil, ErrInvalidRepositoryInput
	}
	report, err := s.Get(ctx, organizationID, reportID)
	if err != nil {
		return nil, err
	}
	asset, trust, results, err := hydrateForensicReportData(report.ReportData)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	approval := &forensicReportApproval{AnalystID: userID, ApprovedAt: now, Note: strings.TrimSpace(note)}
	pdf := renderForensicReportPDF(asset, trust, results, approval)
	digest := sha256.Sum256(pdf)
	hash := hex.EncodeToString(digest[:])
	report.ReportData["approval"] = map[string]any{"analyst_id": userID.String(), "approved_at": now, "approval_note": approval.Note, "signature_type": "AUDITABLE_ANALYST_APPROVAL"}
	jsonData, err := json.Marshal(report.ReportData)
	if err != nil {
		return nil, err
	}
	row := s.repository.databasePool.QueryRow(ctx, `UPDATE media_forensic_reports SET status='APPROVED',approved_by=$3,approved_at=$4,approval_note=$5,report_data=$6,document_pdf=$7,document_sha256=$8,updated_at=CURRENT_TIMESTAMP WHERE organization_id=$1 AND id=$2 RETURNING id,organization_id,media_asset_id,incident_id,report_number,status,report_data,document_sha256,generated_by,generated_at,approved_by,approved_at,approval_note`, organizationID, reportID, userID, now, approval.Note, jsonData, pdf, hash)
	return scanForensicReport(row)
}

func hydrateForensicReportData(data map[string]any) (*MediaAnalysisAsset, *MediaTrustAssessment, []*AnalysisResultBundle, error) {
	asset := &MediaAnalysisAsset{}
	assetData, ok := data["asset"]
	if !ok {
		return nil, nil, nil, ErrInvalidRepositoryInput
	}
	encodedAsset, err := json.Marshal(assetData)
	if err != nil || json.Unmarshal(encodedAsset, asset) != nil || asset.ID == uuid.Nil {
		return nil, nil, nil, ErrInvalidRepositoryInput
	}
	var trust *MediaTrustAssessment
	if trustData, exists := data["trust_assessment"]; exists {
		trust = &MediaTrustAssessment{}
		encodedTrust, marshalErr := json.Marshal(trustData)
		if marshalErr != nil || json.Unmarshal(encodedTrust, trust) != nil {
			return nil, nil, nil, ErrInvalidRepositoryInput
		}
	}
	results := make([]*AnalysisResultBundle, 0)
	if resultData, exists := data["analysis_results"]; exists {
		encodedResults, marshalErr := json.Marshal(resultData)
		if marshalErr != nil || json.Unmarshal(encodedResults, &results) != nil {
			return nil, nil, nil, ErrInvalidRepositoryInput
		}
	}
	return asset, trust, results, nil
}
func (s *ForensicReportService) SetAccessPassword(ctx context.Context, organizationID, reportID uuid.UUID, password string) error {
	if s == nil || ctx == nil || len(password) < 12 || len(password) > 128 {
		return ErrInvalidRepositoryInput
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil { return err }
	command, err := s.repository.databasePool.Exec(ctx, `UPDATE media_forensic_reports SET access_password_hash=$3,access_password_set_at=NOW(),updated_at=CURRENT_TIMESTAMP WHERE organization_id=$1 AND id=$2`, organizationID, reportID, string(hash))
	if err != nil { return err }
	if command.RowsAffected() == 0 { return ErrForensicReportNotFound }
	return nil
}

func (s *ForensicReportService) PDF(ctx context.Context, organizationID, reportID uuid.UUID, password string) ([]byte, string, error) {
	if s == nil || ctx == nil {
		return nil, "", ErrInvalidRepositoryInput
	}
	var pdf []byte
	var number string
	var passwordHash *string
	err := s.repository.databasePool.QueryRow(ctx, `SELECT document_pdf,report_number,access_password_hash FROM media_forensic_reports WHERE organization_id=$1 AND id=$2`, organizationID, reportID).Scan(&pdf, &number, &passwordHash)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, "", ErrForensicReportNotFound
		}
		return nil, "", err
	}
	if passwordHash != nil && *passwordHash != "" {
		if strings.TrimSpace(password) == "" { return nil, "", ErrForensicReportPasswordRequired }
		if bcrypt.CompareHashAndPassword([]byte(*passwordHash), []byte(password)) != nil { return nil, "", ErrForensicReportPasswordInvalid }
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

func renderForensicReportPDF(asset *MediaAnalysisAsset, trust *MediaTrustAssessment, results []*AnalysisResultBundle, approval *forensicReportApproval) []byte {
	lines := []string{
		"DEEPFAKE AND SYNTHETIC MEDIA FORENSIC ANALYSIS",
		"",
		"Evidence identity and chain of custody",
		"Asset ID: " + asset.ID.String(),
		"File: " + asset.OriginalFileName,
		"SHA-256 (" + asset.HashAlgorithm + "): " + asset.FileHash,
		"Media type: " + asset.MediaType,
		fmt.Sprintf("File size: %d bytes", asset.FileSizeBytes),
		"Source type: " + asset.SourceType,
		"Uploaded at (UTC): " + asset.UploadedAt.UTC().Format(time.RFC3339),
		"",
	}
	if trust != nil {
		lines = append(lines, "Verdict: "+trust.Verdict, fmt.Sprintf("Trust score: %.2f", trust.TrustScore), fmt.Sprintf("Risk score: %.2f", trust.RiskScore), fmt.Sprintf("Confidence: %.2f", trust.ConfidenceScore), "")
	}
	lines = append(lines, fmt.Sprintf("Completed analysis results: %d", len(results)))
	for index, result := range results {
		lines = appendForensicResultLines(lines, index+1, result)
	}
	if approval != nil {
		lines = append(lines, "", "Analyst approval / signature", "Analyst user ID: "+approval.AnalystID.String(), "Approved at (UTC): "+approval.ApprovedAt.UTC().Format(time.RFC3339), "Approval note: "+reportTextSnippet(approval.Note, 500))
	} else {
		lines = append(lines, "", "Analyst approval: pending. Approval is recorded with analyst identity, timestamp and note through the approval API.")
	}
	lines = append(lines, "This report is AI-assisted and requires analyst approval.")
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

func appendForensicResultLines(lines []string, number int, result *AnalysisResultBundle) []string {
	if result == nil {
		return lines
	}
	prefix := fmt.Sprintf("Analysis %d", number)
	if result.Deepfake != nil {
		deepfake := result.Deepfake
		lines = append(lines, prefix+" deepfake: "+deepfake.DetectionResult)
		if deepfake.DeepfakeProbability != nil {
			lines = append(lines, fmt.Sprintf("  Deepfake probability: %.2f%%", *deepfake.DeepfakeProbability))
		}
		if deepfake.ConfidenceScore != nil {
			lines = append(lines, fmt.Sprintf("  Confidence: %.2f%%", *deepfake.ConfidenceScore))
		}
		if deepfake.SuspiciousFrames != nil {
			lines = append(lines, fmt.Sprintf("  Suspicious frames: %d", *deepfake.SuspiciousFrames))
		}
		if len(deepfake.SuspiciousRegions) > 0 {
			lines = append(lines, fmt.Sprintf("  Suspicious regions: %d recorded", len(deepfake.SuspiciousRegions)))
		}
		if deepfake.DetectionSummary != nil {
			lines = append(lines, "  Summary: "+reportTextSnippet(*deepfake.DetectionSummary, 300))
		}
	}
	if result.Forensics != nil {
		forensics := result.Forensics
		lines = append(lines, prefix+" classical forensics: "+forensics.ForensicResult)
		if len(forensics.SuspiciousLocations) > 0 {
			lines = append(lines, fmt.Sprintf("  Suspicious locations: %d recorded", len(forensics.SuspiciousLocations)))
		}
		if forensics.AnalysisSummary != nil {
			lines = append(lines, "  Summary: "+reportTextSnippet(*forensics.AnalysisSummary, 300))
		}
	}
	if result.OCR != nil {
		ocr := result.OCR
		lines = append(lines, prefix+" OCR: "+ocr.ExtractionResult)
		if ocr.OCREngine != nil {
			lines = append(lines, "  OCR engine: "+*ocr.OCREngine)
		}
		if ocr.ExtractedText != nil {
			lines = append(lines, "  OCR text: "+reportTextSnippet(*ocr.ExtractedText, 500))
		}
	}
	return lines
}

func reportTextSnippet(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func escapePDFText(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "(", "\\(")
	value = strings.ReplaceAll(value, ")", "\\)")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}
