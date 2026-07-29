package deepfakeforensics

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRenderForensicReportPDFIncludesEvidenceIdentity(t *testing.T) {
	asset := &MediaAnalysisAsset{ID: uuid.New(), OrganizationID: uuid.New(), OriginalFileName: "sample.pdf", MediaType: "DOCUMENT", FileHash: strings.Repeat("a", 64)}
	trust := &MediaTrustAssessment{Verdict: TrustVerdictSuspicious, TrustScore: 35, RiskScore: 65, ConfidenceScore: 88}
	pdf := renderForensicReportPDF(asset, trust, nil)
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
}
