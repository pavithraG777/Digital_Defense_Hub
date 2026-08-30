package honeytoken

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

const ownerProtectedFileRestoreChallengeLifetime = 10 * time.Minute

var (
	ErrOwnerEmailNotVerified          = errors.New("owner email address is not verified")
	ErrOwnerOTPDeliveryUnavailable    = errors.New("OTP delivery is unavailable")
	ErrOwnerAuthenticationUnavailable = errors.New("owner authentication is unavailable")
)

type ProtectedFileService interface {
	RegisterProtectedFile(ctx context.Context, req *RegisterProtectedFileRequest) (*RegisterProtectedFileResponse, error)
	GetProtectedFile(ctx context.Context, protectedFileID uuid.UUID) (*ProtectedFile, error)
	RestoreProtectedFile(ctx context.Context, protectedFileID uuid.UUID, organizationID uuid.UUID, req *RestoreProtectedFileRequest) (*RestoreProtectedFileResponse, error)
}

type Handler struct {
	service        ProtectedFileService
	authRepository auth.MFAChallengeRepository
	mfaDelivery    auth.MFAOTPDelivery
}

func NewHandler(
	service ProtectedFileService,
	authRepository auth.MFAChallengeRepository,
	mfaDelivery auth.MFAOTPDelivery,
) *Handler {
	return &Handler{
		service:        service,
		authRepository: authRepository,
		mfaDelivery:    mfaDelivery,
	}
}

// RegisterProtectedFile validates the authenticated tenant and user,
// protects the requested file and returns its vault registration details.
func (h *Handler) RegisterProtectedFile(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Protected file handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := protectedFileUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	ownerUserID, ok := protectedFileUUIDFromContext(
		c,
		"user_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return
	}

	var request RegisterProtectedFileRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid request payload",
			err.Error(),
		)
		return
	}

	if err := validateRegisterProtectedFileRequest(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid protected file request",
			err.Error(),
		)
		return
	}

	if _, err := parseOptionalDepartmentID(
		request.DepartmentID,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid protected file request",
			err.Error(),
		)
		return
	}

	if !requestIdentityMatches(
		request.OrganizationID,
		organizationID,
	) {
		response.Forbidden(
			c,
			"Organization ID does not match the authenticated organization",
			nil,
		)
		return
	}

	if !requestIdentityMatches(
		request.OwnerUserID,
		ownerUserID,
	) {
		response.Forbidden(
			c,
			"Owner user ID does not match the authenticated user",
			nil,
		)
		return
	}

	// Always use trusted authentication values after verifying the payload.
	request.OrganizationID = organizationID.String()
	request.OwnerUserID = ownerUserID.String()

	registration, err := h.service.RegisterProtectedFile(
		c.Request.Context(),
		&request,
	)
	if err != nil {
		handleProtectedFileRegistrationError(
			c,
			err,
		)
		return
	}

	response.Created(
		c,
		"Protected file registered successfully",
		registration,
	)
}

// GetProtectedFile returns safe protected-file metadata without exposing
// local storage paths, encryption key identifiers or cryptographic hashes.
func (h *Handler) GetProtectedFile(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Protected file handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := protectedFileUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	protectedFileID, err := uuid.Parse(
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil {
		response.BadRequest(
			c,
			"Invalid protected file ID",
			err.Error(),
		)
		return
	}

	file, err := h.service.GetProtectedFile(
		c.Request.Context(),
		protectedFileID,
	)
	if err != nil {
		handleGetProtectedFileError(
			c,
			err,
		)
		return
	}

	if file == nil {
		internalError := errors.New(
			"protected file service returned an empty result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to retrieve protected file",
			nil,
		)
		return
	}

	// Hide records belonging to another organization.
	if file.OrganizationID != organizationID {
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)
		return
	}

	response.OK(
		c,
		"Protected file retrieved successfully",
		buildGetProtectedFileResponse(file),
	)
}

// StartOwnerProtectedFileRestore sends an email OTP challenge to the
// owner of the protected file before restoration can proceed.
func (h *Handler) StartOwnerProtectedFileRestore(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Protected file handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := protectedFileUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	ownerUserID, ok := protectedFileUUIDFromContext(
		c,
		"user_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return
	}

	protectedFileID, err := uuid.Parse(
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil {
		response.BadRequest(
			c,
			"Invalid protected file ID",
			err.Error(),
		)
		return
	}

	file, err := h.service.GetProtectedFile(
		c.Request.Context(),
		protectedFileID,
	)
	if err != nil {
		handleOwnerRestoreError(c, err)
		return
	}

	if file == nil || file.OrganizationID != organizationID {
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)
		return
	}

	if file.OwnerUserID != ownerUserID {
		response.Forbidden(
			c,
			"Only the protected file owner can initiate restoration",
			nil,
		)
		return
	}

	user, err := h.authRepository.FindUserByID(
		c.Request.Context(),
		ownerUserID,
	)
	if err != nil {
		response.InternalServerError(
			c,
			"Failed to verify owner identity",
			err.Error(),
		)
		return
	}

	if !user.EmailVerified {
		response.Error(
			c,
			http.StatusForbidden,
			"Owner email address is not verified",
			nil,
		)
		return
	}

	challenge, err := h.createOwnerOTPChallenge(
		c.Request.Context(),
		user,
	)
	if err != nil {
		handleOwnerRestoreError(c, err)
		return
	}

	response.Accepted(
		c,
		"OTP challenge created successfully",
		challenge,
	)
}

func (h *Handler) RestoreProtectedFileOwner(
	c *gin.Context,
) {
	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Protected file handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := protectedFileUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	ownerUserID, ok := protectedFileUUIDFromContext(
		c,
		"user_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return
	}

	protectedFileID, err := uuid.Parse(
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil {
		response.BadRequest(
			c,
			"Invalid protected file ID",
			err.Error(),
		)
		return
	}

	var request RestoreProtectedFileOwnerRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid restore request payload",
			err.Error(),
		)
		return
	}

	if err := validateRestoreProtectedFileRequest(&RestoreProtectedFileRequest{
		RestoreReason: request.RestoreReason,
	}); err != nil {
		response.BadRequest(
			c,
			"Invalid restore request",
			err.Error(),
		)
		return
	}

	file, err := h.service.GetProtectedFile(
		c.Request.Context(),
		protectedFileID,
	)
	if err != nil {
		handleOwnerRestoreError(c, err)
		return
	}

	if file == nil || file.OrganizationID != organizationID {
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)
		return
	}

	if file.OwnerUserID != ownerUserID {
		response.Forbidden(
			c,
			"Only the protected file owner can restore this file",
			nil,
		)
		return
	}

	user, err := h.authRepository.FindUserByID(c.Request.Context(), ownerUserID)
	if err != nil || user == nil || !auth.VerifyPassword(request.Password, user.PasswordHash) {
		response.Forbidden(c, "Protected file password is invalid", nil)
		return
	}
	trusted, err := h.authRepository.IsDeviceTrusted(c.Request.Context(), ownerUserID, organizationID, strings.TrimSpace(request.DeviceID))
	if err != nil || !trusted {
		response.Forbidden(c, "This device is not approved for protected-file restore", nil)
		return
	}
	if !approvedProtectedFileIP(c.ClientIP()) {
		response.Forbidden(c, "This IP address is not approved for protected-file restore", nil)
		return
	}

	if _, err := h.verifyOwnerOTPChallenge(
		c.Request.Context(),
		ownerUserID,
		organizationID,
		request,
	); err != nil {
		handleOwnerRestoreError(c, err)
		return
	}

	result, err := h.service.RestoreProtectedFile(
		c.Request.Context(),
		protectedFileID,
		organizationID,
		&RestoreProtectedFileRequest{RestoreReason: request.RestoreReason},
	)
	if err != nil {
		handleRestoreProtectedFileError(c, err)
		return
	}

	if result == nil {
		internalError := errors.New(
			"protected file restore returned an empty result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to restore protected file",
			nil,
		)
		return
	}

	if request.Download {
		temporaryDirectory := filepath.Dir(
			filepath.Join(
				protectedFileRestoreStorageDirectory,
				organizationID.String(),
				protectedFileID.String(),
				result.RestoredFileName,
			),
		)
		temporaryPath := filepath.Join(
			protectedFileRestoreStorageDirectory,
			organizationID.String(),
			protectedFileID.String(),
			result.RestoredFileName,
		)
		defer os.Remove(temporaryPath)
		defer os.Remove(temporaryDirectory)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", result.RestoredFileName))
		c.Header("Content-Type", "application/octet-stream")
		http.ServeFile(c.Writer, c.Request, temporaryPath)
		return
	}

	response.OK(
		c,
		"Protected file restored successfully",
		result,
	)
}

func approvedProtectedFileIP(clientIP string) bool {
	allowed := strings.TrimSpace(os.Getenv("PROTECTED_FILE_APPROVED_IPS"))
	if allowed == "" {
		return true
	}
	for _, value := range strings.Split(allowed, ",") {
		if strings.TrimSpace(value) == clientIP {
			return true
		}
	}
	return false
}

func (h *Handler) isAvailable() bool {
	return h != nil && h.service != nil
}

func (h *Handler) createOwnerOTPChallenge(
	ctx context.Context,
	user *auth.User,
) (*StartOwnerProtectedFileRestoreResponse, error) {
	if user == nil {
		return nil, ErrOwnerAuthenticationUnavailable
	}

	if !user.EmailVerified {
		return nil, ErrOwnerEmailNotVerified
	}

	if h.authRepository == nil || h.mfaDelivery == nil {
		return nil, ErrOwnerAuthenticationUnavailable
	}

	otp, err := generateOwnerOTP()
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP: %w", err)
	}

	hashedOTP, err := bcrypt.GenerateFromPassword([]byte(otp), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash OTP: %w", err)
	}

	expiresAt := time.Now().UTC().Add(ownerProtectedFileRestoreChallengeLifetime)

	challengeID, err := h.authRepository.CreateMFAChallenge(
		ctx,
		user.ID,
		user.OrganizationID,
		string(hashedOTP),
		string(hashedOTP),
		expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create MFA challenge: %w", err)
	}

	if err := h.mfaDelivery.DeliverMFAOTP(
		ctx,
		user.OfficialEmail,
		otp,
	); err != nil {
		_ = h.authRepository.CancelMFAChallenge(ctx, challengeID)
		return nil, fmt.Errorf("%w: failed to deliver OTP: %v", ErrOwnerOTPDeliveryUnavailable, err)
	}

	return &StartOwnerProtectedFileRestoreResponse{
		MFAChallengeID:   challengeID.String(),
		ExpiresInSeconds: int64(ownerProtectedFileRestoreChallengeLifetime.Seconds()),
	}, nil
}

func (h *Handler) verifyOwnerOTPChallenge(
	ctx context.Context,
	userID uuid.UUID,
	organizationID uuid.UUID,
	request RestoreProtectedFileOwnerRequest,
) (*auth.MFAChallenge, error) {
	if h.authRepository == nil {
		return nil, ErrOwnerAuthenticationUnavailable
	}

	challengeID, err := uuid.Parse(
		strings.TrimSpace(request.MFAChallengeID),
	)
	if err != nil {
		return nil, auth.ErrMFAChallengeInvalid
	}

	challenge, err := h.authRepository.VerifyAndConsumeMFAChallenge(
		ctx,
		challengeID,
		request.EmailCode,
		request.EmailCode,
	)
	if err != nil {
		return nil, err
	}

	if challenge.UserID != userID || challenge.OrganizationID != organizationID {
		return nil, auth.ErrMFAChallengeInvalid
	}

	return challenge, nil
}

func generateOwnerOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func handleOwnerRestoreError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrOwnerEmailNotVerified):
		response.Error(
			c,
			http.StatusForbidden,
			"Owner email address is not verified",
			nil,
		)

	case errors.Is(err, ErrOwnerOTPDeliveryUnavailable):
		response.Error(
			c,
			http.StatusServiceUnavailable,
			"OTP delivery is unavailable",
			nil,
		)

	case errors.Is(err, ErrOwnerAuthenticationUnavailable):
		response.InternalServerError(
			c,
			"Owner authentication is unavailable",
			nil,
		)

	case errors.Is(err, auth.ErrMFAChallengeInvalid), errors.Is(err, auth.ErrMFAChallengeLocked):
		response.Unauthorized(
			c,
			"OTP verification failed",
			nil,
		)

	case errors.Is(err, ErrProtectedFileNotFound):
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)

	default:
		_ = c.Error(err)
		response.InternalServerError(
			c,
			"Failed to process owner restore request",
			nil,
		)
	}
}

func protectedFileUUIDFromContext(
	c *gin.Context,
	key string,
) (uuid.UUID, bool) {
	if c == nil {
		return uuid.Nil, false
	}

	value, exists := c.Get(key)
	if !exists {
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
		parsedValue, err := uuid.Parse(
			strings.TrimSpace(typedValue),
		)
		if err != nil || parsedValue == uuid.Nil {
			return uuid.Nil, false
		}

		return parsedValue, true

	default:
		return uuid.Nil, false
	}
}

func requestIdentityMatches(
	requestValue string,
	authenticatedValue uuid.UUID,
) bool {
	requestID, err := uuid.Parse(
		strings.TrimSpace(requestValue),
	)
	if err != nil {
		return false
	}

	return requestID == authenticatedValue
}

func handleProtectedFileRegistrationError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrSourceFileNotFound):
		response.NotFound(
			c,
			"Source file was not found",
			nil,
		)

	case errors.Is(err, ErrInvalidSourceFile):
		response.BadRequest(
			c,
			"Source path must point to a regular file",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Protected file registration timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to register protected file",
			nil,
		)
	}
}

func handleGetProtectedFileError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrProtectedFileNotFound):
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Protected file request timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to retrieve protected file",
			nil,
		)
	}
}

func buildGetProtectedFileResponse(
	file *ProtectedFile,
) *GetProtectedFileResponse {
	departmentID := ""

	if file.DepartmentID != nil {
		departmentID = file.DepartmentID.String()
	}

	return &GetProtectedFileResponse{
		ID:             file.ID.String(),
		OrganizationID: file.OrganizationID.String(),
		DepartmentID:   departmentID,
		OwnerUserID:    file.OwnerUserID.String(),

		OriginalFileName:  file.OriginalFileName,
		ProtectedFileName: file.ProtectedFileName,

		Category:       file.Category,
		Sensitivity:    file.Sensitivity,
		Classification: file.Classification,

		FileSizeBytes: file.FileSizeBytes,
		MimeType:      file.MimeType,
		Status:        file.Status,

		MonitoringEnabled: file.MonitoringEnabled,
		HoneytokenEnabled: file.HoneytokenEnabled,
		CanaryEnabled:     file.CanaryEnabled,

		CreatedAt: file.CreatedAt.
			UTC().
			Format(time.RFC3339),
	}
}

// RestoreProtectedFile handles an authorized request to decrypt and
// restore an original file from its protected .ddh package.
func (h *Handler) RestoreProtectedFile(
	c *gin.Context,
) {
	response.Forbidden(
		c,
		"Direct protected-file restore is disabled; use the owner MFA/password restore flow",
		nil,
	)
	return

	if !h.isAvailable() {
		response.InternalServerError(
			c,
			"Protected file handler is unavailable",
			nil,
		)
		return
	}

	organizationID, ok := protectedFileUUIDFromContext(
		c,
		"organization_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"Organization information is missing",
			nil,
		)
		return
	}

	ownerUserID, ok := protectedFileUUIDFromContext(
		c,
		"user_id",
	)
	if !ok {
		response.Unauthorized(
			c,
			"User information is missing",
			nil,
		)
		return
	}

	protectedFileID, err := uuid.Parse(
		strings.TrimSpace(c.Param("id")),
	)
	if err != nil {
		response.BadRequest(
			c,
			"Invalid protected file ID",
			err.Error(),
		)
		return
	}

	var request RestoreProtectedFileRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(
			c,
			"Invalid restore request payload",
			err.Error(),
		)
		return
	}

	if err := validateRestoreProtectedFileRequest(
		&request,
	); err != nil {
		response.BadRequest(
			c,
			"Invalid restore request",
			err.Error(),
		)
		return
	}

	file, err := h.service.GetProtectedFile(
		c.Request.Context(),
		protectedFileID,
	)
	if err != nil {
		handleRestoreProtectedFileError(
			c,
			err,
		)
		return
	}

	if file == nil || file.OrganizationID != organizationID {
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)
		return
	}

	if file.OwnerUserID != ownerUserID {
		response.Forbidden(
			c,
			"Only the protected file owner can restore this file",
			nil,
		)
		return
	}

	result, err := h.service.RestoreProtectedFile(
		c.Request.Context(),
		protectedFileID,
		organizationID,
		&request,
	)
	if err != nil {
		handleRestoreProtectedFileError(
			c,
			err,
		)
		return
	}

	if result == nil {
		internalError := errors.New(
			"protected file restore returned an empty result",
		)

		_ = c.Error(internalError)

		response.InternalServerError(
			c,
			"Failed to restore protected file",
			nil,
		)
		return
	}

	response.OK(
		c,
		"Protected file restored successfully",
		result,
	)
}

func handleRestoreProtectedFileError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrProtectedFileNotFound):
		response.NotFound(
			c,
			"Protected file not found",
			nil,
		)

	case errors.Is(err, ErrProtectedPackageNotFound):
		response.NotFound(
			c,
			"Protected package was not found",
			nil,
		)

	case errors.Is(err, ErrRestoreTargetAlreadyExists):
		response.Error(
			c,
			http.StatusConflict,
			"Restored file already exists",
			nil,
		)

	case errors.Is(err, ErrProtectedFileNotRestorable):
		response.Error(
			c,
			http.StatusConflict,
			"Protected file cannot be restored in its current state",
			nil,
		)

	case errors.Is(err, ErrInvalidProtectedPackage),
		errors.Is(err, ErrProtectedPackageAuthenticationFailed),
		errors.Is(err, ErrDecryptedFileIntegrityCheckFailed):
		response.Error(
			c,
			http.StatusUnprocessableEntity,
			"Protected package failed security verification",
			nil,
		)

	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		response.Error(
			c,
			http.StatusRequestTimeout,
			"Protected file restoration timed out",
			nil,
		)

	default:
		_ = c.Error(err)

		response.InternalServerError(
			c,
			"Failed to restore protected file",
			nil,
		)
	}
}
