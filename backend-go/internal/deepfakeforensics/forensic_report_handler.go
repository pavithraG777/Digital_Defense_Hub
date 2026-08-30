package deepfakeforensics

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

func (h *Handler) ListMediaForensicReports(c *gin.Context) {
	organizationID, _, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	reports, err := h.reportService.List(c.Request.Context(), organizationID, page, pageSize)
	if err != nil {
		handleForensicReportError(c, err)
		return
	}
	response.OK(c, "Media forensic reports retrieved successfully", reports)
}

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
	var request ForensicReportPDFRequest
	if err := c.ShouldBindJSON(&request); err != nil { response.BadRequest(c, "Invalid report access request", nil); return }
	pdf, number, err := h.reportService.PDF(c.Request.Context(), organizationID, reportID, request.AccessPassword)
	if err != nil {
		handleForensicReportError(c, err)
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+strings.ReplaceAll(number, "\"", "")+".pdf")
	c.Data(http.StatusOK, "application/pdf", pdf)
}

func (h *Handler) PreviewMediaForensicReport(c *gin.Context) {
	organizationID, _, ok := h.authenticatedIdentity(c); if !ok { return }
	reportID, ok := handlerPathUUID(c, "report_id"); if !ok { response.BadRequest(c, "Invalid report ID", nil); return }
	var request ForensicReportPDFRequest
	if err := c.ShouldBindJSON(&request); err != nil { response.BadRequest(c, "Invalid report access request", nil); return }
	pdf, _, err := h.reportService.PDF(c.Request.Context(), organizationID, reportID, request.AccessPassword)
	if err != nil { handleForensicReportError(c, err); return }
	c.Header("Content-Disposition", "inline")
	c.Data(http.StatusOK, "application/pdf", pdf)
}

func (h *Handler) SetMediaForensicReportAccessPassword(c *gin.Context) {
	organizationID, _, ok := h.authenticatedIdentity(c); if !ok { return }
	reportID, ok := handlerPathUUID(c, "report_id"); if !ok { response.BadRequest(c, "Invalid report ID", nil); return }
	var request SetForensicReportAccessPasswordRequest
	if err := c.ShouldBindJSON(&request); err != nil { response.BadRequest(c, "Use a password of at least 12 characters", nil); return }
	if err := h.reportService.SetAccessPassword(c.Request.Context(), organizationID, reportID, request.AccessPassword); err != nil { handleForensicReportError(c, err); return }
	response.OK(c, "Forensic report access password set successfully", map[string]bool{"access_password_configured": true})
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
	if errors.Is(err, ErrForensicReportPasswordRequired) || errors.Is(err, ErrForensicReportPasswordInvalid) {
		response.Forbidden(c, "Forensic report access password is required or invalid", nil)
		return
	}
	_ = c.Error(err)
	response.InternalServerError(c, "Media forensic report operation failed", nil)
}
