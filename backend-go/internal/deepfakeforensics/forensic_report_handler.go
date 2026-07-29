package deepfakeforensics

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

func (h *Handler) CreateMediaForensicReport(c *gin.Context) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	assetID, ok := handlerPathUUID(c, "media_asset_id")
	if !ok {
		response.BadRequest(c, "Invalid media asset ID", nil)
		return
	}
	report, err := h.reportService.Create(c.Request.Context(), organizationID, assetID, userID)
	if err != nil {
		handleForensicReportError(c, err)
		return
	}
	response.Created(c, "Media forensic report generated successfully", report)
}

func (h *Handler) GetMediaForensicReport(c *gin.Context) {
	organizationID, _, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	reportID, ok := handlerPathUUID(c, "report_id")
	if !ok {
		response.BadRequest(c, "Invalid report ID", nil)
		return
	}
	report, err := h.reportService.Get(c.Request.Context(), organizationID, reportID)
	if err != nil {
		handleForensicReportError(c, err)
		return
	}
	response.OK(c, "Media forensic report retrieved successfully", report)
}

func (h *Handler) ApproveMediaForensicReport(c *gin.Context) {
	organizationID, userID, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	reportID, ok := handlerPathUUID(c, "report_id")
	if !ok {
		response.BadRequest(c, "Invalid report ID", nil)
		return
	}
	var request ApproveMediaForensicReportRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid report approval request", err.Error())
		return
	}
	report, err := h.reportService.Approve(c.Request.Context(), organizationID, reportID, userID, request.ApprovalNote)
	if err != nil {
		handleForensicReportError(c, err)
		return
	}
	response.OK(c, "Media forensic report approved successfully", report)
}

func (h *Handler) DownloadMediaForensicReport(c *gin.Context) {
	organizationID, _, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	reportID, ok := handlerPathUUID(c, "report_id")
	if !ok {
		response.BadRequest(c, "Invalid report ID", nil)
		return
	}
	pdf, number, err := h.reportService.PDF(c.Request.Context(), organizationID, reportID)
	if err != nil {
		handleForensicReportError(c, err)
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+strings.ReplaceAll(number, "\"", "")+".pdf")
	c.Data(http.StatusOK, "application/pdf", pdf)
}

func handleForensicReportError(c *gin.Context, err error) {
	if errors.Is(err, ErrForensicReportNotFound) || errors.Is(err, ErrMediaAssetNotFound) {
		response.NotFound(c, "Media forensic report resource not found", nil)
		return
	}
	if errors.Is(err, ErrInvalidRepositoryInput) {
		response.BadRequest(c, "Invalid media forensic report request", nil)
		return
	}
	_ = c.Error(err)
	response.InternalServerError(c, "Media forensic report operation failed", nil)
}
