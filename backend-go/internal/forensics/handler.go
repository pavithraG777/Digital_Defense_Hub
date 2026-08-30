package forensics

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) (*Handler, error) {
	if service == nil {
		return nil, errors.New("forensics service is required")
	}

	return &Handler{service: service}, nil
}

type createCaseRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	IncidentIDs []string `json:"incident_ids"`
}

type addEvidenceRequest struct {
	EvidenceType string         `json:"evidence_type"`
	SourceType   string         `json:"source_type"`
	SourcePath   string         `json:"source_path"`
	FileHash     string         `json:"file_hash"`
	Metadata     map[string]any `json:"metadata"`
}

type createAnalysisResultRequest struct {
	AnalysisJobID   string         `json:"analysis_job_id"`
	CaseID          string         `json:"case_id,omitempty"`
	EvidenceID      string         `json:"evidence_id,omitempty"`
	EvidenceFileID  string         `json:"evidence_file_id,omitempty"`
	ResultType      string         `json:"result_type"`
	Result          string         `json:"result"`
	ConfidenceScore *float64       `json:"confidence_score,omitempty"`
	Summary         string         `json:"summary,omitempty"`
	Findings        []string       `json:"findings,omitempty"`
	ResultData      map[string]any `json:"result_data,omitempty"`
}

func (h *Handler) Health(c *gin.Context) {
	response.OK(c, "Forensics API is available", gin.H{})
}

func (h *Handler) CreateCase(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "Forensics handler is unavailable", nil)
		return
	}

	var req createCaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid create case payload", err.Error())
		return
	}

	organizationID, ok := handlerContextUUID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization context is missing", nil)
		return
	}

	result, err := h.service.CreateCase(
		c.Request.Context(),
		organizationID,
		req.Title,
		req.Description,
		req.IncidentIDs,
	)
	if err != nil {
		response.BadRequest(c, "Failed to create forensic case", err.Error())
		return
	}

	response.Created(c, "Forensic case created", result)
}

func (h *Handler) ListCases(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "Forensics handler is unavailable", nil)
		return
	}

	organizationID, ok := handlerContextUUID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization context is missing", nil)
		return
	}

	results, err := h.service.ListCases(c.Request.Context(), organizationID)
	if err != nil {
		response.InternalServerError(c, "Failed to list forensic cases", err.Error())
		return
	}

	response.OK(c, "Forensic cases retrieved", results)
}

func (h *Handler) GetCase(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "Forensics handler is unavailable", nil)
		return
	}

	caseID, ok := handlerPathUUID(c, "case_id")
	if !ok {
		response.BadRequest(c, "Invalid case ID", nil)
		return
	}

	result, err := h.service.GetCase(c.Request.Context(), caseID)
	if err != nil {
		if errors.Is(err, ErrCaseNotFound) {
			response.NotFound(c, "Forensic case not found", nil)
			return
		}
		response.InternalServerError(c, "Failed to retrieve forensic case", err.Error())
		return
	}

	response.OK(c, "Forensic case retrieved", result)
}

func (h *Handler) AddEvidence(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "Forensics handler is unavailable", nil)
		return
	}

	caseID, ok := handlerPathUUID(c, "case_id")
	if !ok {
		response.BadRequest(c, "Invalid case ID", nil)
		return
	}

	var req addEvidenceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid evidence payload", err.Error())
		return
	}

	organizationID, ok := handlerContextUUID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization context is missing", nil)
		return
	}

	evidence := &ForensicEvidence{
		CaseID:         caseID,
		OrganizationID: organizationID,
		EvidenceType:   req.EvidenceType,
		SourceType:     req.SourceType,
		SourcePath:     req.SourcePath,
		FileHash:       req.FileHash,
		Metadata:       req.Metadata,
	}

	result, err := h.service.AddEvidence(c.Request.Context(), evidence)
	if err != nil {
		response.BadRequest(c, "Failed to add forensic evidence", err.Error())
		return
	}

	response.Created(c, "Forensic evidence added", result)
}

func (h *Handler) ListEvidence(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "Forensics handler is unavailable", nil)
		return
	}

	caseID, ok := handlerPathUUID(c, "case_id")
	if !ok {
		response.BadRequest(c, "Invalid case ID", nil)
		return
	}

	results, err := h.service.ListEvidence(c.Request.Context(), caseID)
	if err != nil {
		response.InternalServerError(c, "Failed to list forensic evidence", err.Error())
		return
	}

	response.OK(c, "Forensic evidence retrieved", results)
}

func (h *Handler) CreateAnalysisResult(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "Forensics handler is unavailable", nil)
		return
	}

	var req createAnalysisResultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid analysis result payload", err.Error())
		return
	}

	organizationID, ok := handlerContextUUID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization context is missing", nil)
		return
	}

	analysisJobID, err := uuid.Parse(strings.TrimSpace(req.AnalysisJobID))
	if err != nil || analysisJobID == uuid.Nil {
		response.BadRequest(c, "Invalid analysis_job_id", err.Error())
		return
	}

	result := &ForensicAnalysisResult{
		OrganizationID:  organizationID,
		AnalysisJobID:   analysisJobID,
		ResultType:      req.ResultType,
		Result:          req.Result,
		ConfidenceScore: req.ConfidenceScore,
		Summary:         req.Summary,
		Findings:        req.Findings,
		ResultData:      req.ResultData,
	}

	if strings.TrimSpace(req.CaseID) != "" {
		caseID, parseErr := uuid.Parse(strings.TrimSpace(req.CaseID))
		if parseErr != nil || caseID == uuid.Nil {
			response.BadRequest(c, "Invalid case_id", parseErr.Error())
			return
		}
		result.CaseID = &caseID
	}

	if strings.TrimSpace(req.EvidenceID) != "" {
		evidenceID, parseErr := uuid.Parse(strings.TrimSpace(req.EvidenceID))
		if parseErr != nil || evidenceID == uuid.Nil {
			response.BadRequest(c, "Invalid evidence_id", parseErr.Error())
			return
		}
		result.EvidenceID = &evidenceID
	}

	if strings.TrimSpace(req.EvidenceFileID) != "" {
		evidenceFileID, parseErr := uuid.Parse(strings.TrimSpace(req.EvidenceFileID))
		if parseErr != nil || evidenceFileID == uuid.Nil {
			response.BadRequest(c, "Invalid evidence_file_id", parseErr.Error())
			return
		}
		result.EvidenceFileID = &evidenceFileID
	}

	created, err := h.service.CreateAnalysisResult(c.Request.Context(), result)
	if err != nil {
		response.BadRequest(c, "Failed to create analysis result", err.Error())
		return
	}

	response.Created(c, "Forensic analysis result created", created)
}

func (h *Handler) GetAnalysisResult(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "Forensics handler is unavailable", nil)
		return
	}

	analysisJobID, ok := handlerPathUUID(c, "analysis_job_id")
	if !ok {
		response.BadRequest(c, "Invalid analysis job ID", nil)
		return
	}

	result, err := h.service.GetAnalysisResult(c.Request.Context(), analysisJobID)
	if err != nil {
		if errors.Is(err, ErrAnalysisResultNotFound) {
			response.NotFound(c, "Forensic analysis result not found", nil)
			return
		}
		response.InternalServerError(c, "Failed to retrieve analysis result", err.Error())
		return
	}

	response.OK(c, "Forensic analysis result retrieved", result)
}

func (h *Handler) ListAnalysisResults(c *gin.Context) {
	if h == nil || h.service == nil {
		response.InternalServerError(c, "Forensics handler is unavailable", nil)
		return
	}

	organizationID, ok := handlerContextUUID(c, "organization_id")
	if !ok {
		response.Unauthorized(c, "Organization context is missing", nil)
		return
	}

	var caseID *uuid.UUID
	if caseIDParam := strings.TrimSpace(c.Query("case_id")); caseIDParam != "" {
		parsedID, err := uuid.Parse(caseIDParam)
		if err != nil || parsedID == uuid.Nil {
			response.BadRequest(c, "Invalid case_id", err.Error())
			return
		}
		caseID = &parsedID
	}

	results, err := h.service.ListAnalysisResults(c.Request.Context(), organizationID, caseID)
	if err != nil {
		response.InternalServerError(c, "Failed to list analysis results", err.Error())
		return
	}

	response.OK(c, "Forensic analysis results retrieved", results)
}

func handlerContextUUID(c *gin.Context, key string) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}

	value, exists := c.Get(key)
	if !exists || value == nil {
		return uuid.Nil, false
	}

	switch typedValue := value.(type) {
	case uuid.UUID:
		if typedValue == uuid.Nil {
			return uuid.Nil, false
		}
		return typedValue, true
	case *uuid.UUID:
		if typedValue == nil || *typedValue == uuid.Nil {
			return uuid.Nil, false
		}
		return *typedValue, true
	case string:
		parsed, err := uuid.Parse(strings.TrimSpace(typedValue))
		if err != nil || parsed == uuid.Nil {
			return uuid.Nil, false
		}
		return parsed, true
	default:
		return uuid.Nil, false
	}
}

func handlerPathUUID(c *gin.Context, parameterName string) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}

	value, err := uuid.Parse(strings.TrimSpace(c.Param(parameterName)))
	if err != nil || value == uuid.Nil {
		return uuid.Nil, false
	}

	return value, true
}
