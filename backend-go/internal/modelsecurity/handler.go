package modelsecurity

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

type VerifyRequest struct {
	ModelID              string       `json:"model_id" binding:"required"`
	ModelVersion         string       `json:"model_version" binding:"required"`
	ExpectedSHA256       string       `json:"expected_sha256" binding:"required"`
	ObservedSHA256       string       `json:"observed_sha256" binding:"required"`
	AttestationIssuer    string       `json:"attestation_issuer"`
	AttestationReference string       `json:"attestation_reference"`
	ValidationPassed     FlexibleBool `json:"validation_passed"`
}

type FlexibleBool bool

func (b *FlexibleBool) UnmarshalJSON(data []byte) error {
	var native bool
	if err := json.Unmarshal(data, &native); err == nil {
		*b = FlexibleBool(native)
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return errors.New("validation_passed must be true or false")
	}
	parsed, err := strconv.ParseBool(text)
	if err != nil {
		return errors.New("validation_passed must be true or false")
	}
	*b = FlexibleBool(parsed)
	return nil
}

func contextID(c *gin.Context, key string) (uuid.UUID, error) {
	v, ok := c.Get(key)
	if !ok {
		return uuid.Nil, errors.New(key + " missing")
	}
	switch id := v.(type) {
	case uuid.UUID:
		return id, nil
	case string:
		return uuid.Parse(id)
	default:
		return uuid.Nil, errors.New(key + " invalid")
	}
}
func normalizedHash(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return "", errors.New("must be a 64-character SHA-256 hexadecimal digest")
	}
	return value, nil
}

func (h *Handler) VerifyModel(c *gin.Context) {
	if h.repo == nil {
		response.InternalServerError(c, "Model security repository unavailable", nil)
		return
	}
	var req VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid model verification request", err.Error())
		return
	}
	expected, err := normalizedHash(req.ExpectedSHA256)
	if err != nil {
		response.BadRequest(c, "Invalid expected_sha256", err.Error())
		return
	}
	observed, err := normalizedHash(req.ObservedSHA256)
	if err != nil {
		response.BadRequest(c, "Invalid observed_sha256", err.Error())
		return
	}
	orgID, err := contextID(c, "organization_id")
	if err != nil {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	userID, err := contextID(c, "user_id")
	if err != nil {
		response.Unauthorized(c, "Invalid user context", nil)
		return
	}
	integrity := subtle.ConstantTimeCompare([]byte(expected), []byte(observed)) == 1
	attested := strings.TrimSpace(req.AttestationIssuer) != "" && strings.TrimSpace(req.AttestationReference) != ""
	validationPassed := bool(req.ValidationPassed)
	assessment := ScoreModelSecurityRisk(req.ModelID, integrity, attested, !validationPassed)
	status := "VERIFIED"
	if assessment.RequiresReview {
		status = "BLOCKED"
	}
	v := &Verification{ID: uuid.New(), OrganizationID: orgID, ModelID: strings.TrimSpace(req.ModelID), ModelVersion: strings.TrimSpace(req.ModelVersion), ExpectedSHA256: expected, ObservedSHA256: observed, AttestationIssuer: strings.TrimSpace(req.AttestationIssuer), AttestationReference: strings.TrimSpace(req.AttestationReference), ValidationPassed: validationPassed, IntegrityVerified: integrity, Status: status, Assessment: assessment, VerifiedBy: userID, VerifiedAt: time.Now().UTC()}
	if err := h.repo.Create(c.Request.Context(), v); err != nil {
		response.InternalServerError(c, "Could not persist model verification", err.Error())
		return
	}
	response.Created(c, "Model verification completed", v)
}
func (h *Handler) CheckIntegrity(c *gin.Context) {
	orgID, err := contextID(c, "organization_id")
	if err != nil {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	s, err := h.repo.Summary(c.Request.Context(), orgID)
	if err != nil {
		response.InternalServerError(c, "Could not load integrity posture", err.Error())
		return
	}
	response.OK(c, "Model integrity posture loaded", s)
}
func (h *Handler) ListVerifications(c *gin.Context) {
	orgID, err := contextID(c, "organization_id")
	if err != nil {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit < 1 || limit > 100 {
		limit = 50
	}
	values, err := h.repo.List(c.Request.Context(), orgID, limit)
	if err != nil {
		response.InternalServerError(c, "Could not list model verifications", err.Error())
		return
	}
	response.OK(c, "Model verifications loaded", values)
}
func (h *Handler) GetVerification(c *gin.Context) {
	orgID, err := contextID(c, "organization_id")
	if err != nil {
		response.Unauthorized(c, "Invalid organization context", nil)
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid verification ID", nil)
		return
	}
	v, err := h.repo.Get(c.Request.Context(), orgID, id)
	if errors.Is(err, ErrVerificationNotFound) {
		response.NotFound(c, "Model verification not found", nil)
		return
	}
	if err != nil {
		response.InternalServerError(c, "Could not load model verification", err.Error())
		return
	}
	response.OK(c, "Model verification loaded", v)
}
