package deepfakeforensics

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type fakeQueryService struct {
	getMediaAssetFn     func(ctx context.Context, organizationID uuid.UUID, mediaAssetID uuid.UUID) (*MediaAnalysisAsset, error)
	listMediaAssetsFn   func(ctx context.Context, organizationID uuid.UUID, filter MediaAssetListFilter) (*MediaAssetListResponse, error)
	getAnalysisJobFn    func(ctx context.Context, organizationID uuid.UUID, analysisJobID uuid.UUID) (*AIAnalysisJob, error)
	listAnalysisJobsFn  func(ctx context.Context, organizationID uuid.UUID, filter AnalysisJobListFilter) (*AnalysisJobListResponse, error)
	getAnalysisResultFn func(ctx context.Context, organizationID uuid.UUID, analysisJobID uuid.UUID) (*AnalysisResultBundle, error)
}

func (f *fakeQueryService) GetMediaAsset(
	ctx context.Context,
	organizationID uuid.UUID,
	mediaAssetID uuid.UUID,
) (*MediaAnalysisAsset, error) {
	if f.getMediaAssetFn != nil {
		return f.getMediaAssetFn(ctx, organizationID, mediaAssetID)
	}
	return nil, nil
}

func (f *fakeQueryService) ListMediaAssets(
	ctx context.Context,
	organizationID uuid.UUID,
	filter MediaAssetListFilter,
) (*MediaAssetListResponse, error) {
	if f.listMediaAssetsFn != nil {
		return f.listMediaAssetsFn(ctx, organizationID, filter)
	}
	return nil, nil
}

func (f *fakeQueryService) GetAnalysisJob(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*AIAnalysisJob, error) {
	if f.getAnalysisJobFn != nil {
		return f.getAnalysisJobFn(ctx, organizationID, analysisJobID)
	}
	return nil, nil
}

func (f *fakeQueryService) ListAnalysisJobs(
	ctx context.Context,
	organizationID uuid.UUID,
	filter AnalysisJobListFilter,
) (*AnalysisJobListResponse, error) {
	if f.listAnalysisJobsFn != nil {
		return f.listAnalysisJobsFn(ctx, organizationID, filter)
	}
	return nil, nil
}

func (f *fakeQueryService) GetAnalysisResult(
	ctx context.Context,
	organizationID uuid.UUID,
	analysisJobID uuid.UUID,
) (*AnalysisResultBundle, error) {
	if f.getAnalysisResultFn != nil {
		return f.getAnalysisResultFn(ctx, organizationID, analysisJobID)
	}
	return nil, nil
}

func (f *fakeQueryService) isAvailable() bool {
	return f != nil
}

func setupGinContext(t *testing.T, method, path string, body []byte) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(recorder)
	c.Request = req
	return c, recorder
}

type analysisResultResponse struct {
	Success bool                 `json:"success"`
	Message string               `json:"message"`
	Data    AnalysisResultBundle `json:"data"`
}

func strPtr(value string) *string {
	return &value
}

func TestGetAnalysisResult_ReturnsOKWithAnalysisResult(t *testing.T) {
	gin.SetMode(gin.TestMode)

	organizationID := uuid.New()
	analysisJobID := uuid.New()
	expectedBundle := &AnalysisResultBundle{
		Forensics: &MediaForensicsResult{
			ID:             uuid.New(),
			AnalysisJobID:  analysisJobID,
			OrganizationID: organizationID,
			MediaType:      MediaTypeDocument,
			ForensicResult: ForensicResultManipulated,
			CreatedAt:      time.Now().UTC(),
		},
		EvidenceAnalysis: EvidenceAnalysis{
			ID:             uuid.New(),
			OrganizationID: organizationID,
			AnalysisJobID:  &analysisJobID,
			AnalysisType:   JobTypeDocumentForensics,
			AnalysisMethod: AnalysisMethodAIBased,
			AnalysisStatus: AnalysisStatusReviewRequired,
			Result:         strPtr("MANIPULATED"),
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		},
	}

	querier := &fakeQueryService{
		getAnalysisResultFn: func(ctx context.Context, orgID uuid.UUID, jobID uuid.UUID) (*AnalysisResultBundle, error) {
			if orgID != organizationID {
				t.Fatalf("expected organizationID %s, got %s", organizationID, orgID)
			}
			if jobID != analysisJobID {
				t.Fatalf("expected analysisJobID %s, got %s", analysisJobID, jobID)
			}
			return expectedBundle, nil
		},
	}

	h := &Handler{
		assetService:    &AssetService{},
		analysisService: &AnalysisService{},
		queryService:    querier,
		trustService:    &TrustService{},
		modelService:    &ModelManagementService{},
		reportService:   &ForensicReportService{},
		policyService:   &OrganizationMediaPolicyService{},
	}

	c, recorder := setupGinContext(t, http.MethodGet, "/analysis-results/{analysis_job_id}", nil)
	c.Set("organization_id", organizationID)
	c.Set("user_id", uuid.New())
	c.Params = gin.Params{{Key: "analysis_job_id", Value: analysisJobID.String()}}

	h.GetAnalysisResult(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	var payload analysisResultResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unexpected response payload: %v", err)
	}

	if !payload.Success {
		t.Fatal("expected success response")
	}
	if payload.Data.Forensics == nil {
		t.Fatal("expected forensics result in response data")
	}
	if payload.Data.Forensics.ForensicResult != ForensicResultManipulated {
		t.Fatalf("expected forensic result %q, got %q", ForensicResultManipulated, payload.Data.Forensics.ForensicResult)
	}
}

func TestGetAnalysisResult_ReturnsBadRequestForInvalidAnalysisJobID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	organizationID := uuid.New()
	querier := &fakeQueryService{}
	h := &Handler{
		assetService:    &AssetService{},
		analysisService: &AnalysisService{},
		queryService:    querier,
		trustService:    &TrustService{},
		modelService:    &ModelManagementService{},
		reportService:   &ForensicReportService{},
		policyService:   &OrganizationMediaPolicyService{},
	}

	c, recorder := setupGinContext(t, http.MethodGet, "/analysis-results/invalid-id", nil)
	c.Set("organization_id", organizationID)
	c.Set("user_id", uuid.New())
	c.Params = gin.Params{{Key: "analysis_job_id", Value: "not-a-uuid"}}

	h.GetAnalysisResult(c)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}
