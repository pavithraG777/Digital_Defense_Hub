package deepfakeforensics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRenderForensicReportPDFIncludesEvidenceIdentity(t *testing.T) {
	suspiciousFrames := 3
	deepfakeProbability := 73.5
	ocrText := "Invoice total due: 42,000. Review supplier account details."
	asset := &MediaAnalysisAsset{ID: uuid.New(), OrganizationID: uuid.New(), OriginalFileName: "sample.pdf", MediaType: "DOCUMENT", SourceType: "UPLOAD", HashAlgorithm: "SHA256", FileHash: strings.Repeat("a", 64), UploadedAt: time.Now().UTC()}
	trust := &MediaTrustAssessment{Verdict: TrustVerdictSuspicious, TrustScore: 35, RiskScore: 65, ConfidenceScore: 88}
	results := []*AnalysisResultBundle{{Deepfake: &DeepfakeDetectionResult{DetectionResult: "SUSPICIOUS", DeepfakeProbability: &deepfakeProbability, SuspiciousFrames: &suspiciousFrames, SuspiciousRegions: []map[string]any{{"x": 1}}}, OCR: &OCRResult{ExtractionResult: "PARTIAL", ExtractedText: &ocrText}}}
	pdf := renderForensicReportPDF(asset, trust, results, &forensicReportApproval{AnalystID: uuid.New(), ApprovedAt: time.Now().UTC(), Note: "Reviewed by the assigned analyst."})
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) {
		t.Fatal("expected PDF signature")
	}
	if !bytes.Contains(pdf, []byte("14 TL")) {
		t.Fatal("expected PDF line leading for readable report rows")
	}
	if !bytes.Contains(pdf, []byte(asset.FileHash)) {
		t.Fatal("expected SHA-256 in PDF")
	}
	if !bytes.Contains(pdf, []byte(TrustVerdictSuspicious)) {
		t.Fatal("expected trust verdict in PDF")
	}
	for _, expected := range []string{"chain of custody", "Suspicious frames: 3", "Suspicious regions: 1 recorded", "OCR text: Invoice total due", "Analyst approval / signature"} {
		if !bytes.Contains(pdf, []byte(expected)) {
			t.Fatalf("expected PDF to include %q", expected)
		}
	}
}
