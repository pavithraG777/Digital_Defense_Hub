package deepfakeforensics

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

func (h *Handler) GetOrganizationMediaPolicy(c *gin.Context) {
	org, _, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	item, err := h.policyService.Get(c.Request.Context(), org)
	if err != nil {
		handleMediaAPIError(c, err, "Unable to retrieve organization media policy")
		return
	}
	response.OK(c, "Organization media policy retrieved successfully", item)
}
func (h *Handler) UpdateOrganizationMediaPolicy(c *gin.Context) {
	org, user, ok := h.authenticatedIdentity(c)
	if !ok {
		return
	}
	var request UpdateOrganizationMediaPolicyRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid organization media policy", err.Error())
		return
	}
	item, err := h.policyService.Update(c.Request.Context(), org, user, request)
	if err != nil {
		if errors.Is(err, ErrInvalidMediaPolicy) {
			response.BadRequest(c, "Invalid organization media policy", err.Error())
			return
		}
		handleMediaAPIError(c, err, "Unable to update organization media policy")
		return
	}
	response.OK(c, "Organization media policy updated successfully", item)
}
