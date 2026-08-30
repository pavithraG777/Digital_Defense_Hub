package honeytoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
)

type fakeProtectedFileService struct {
	getProtectedFileFn     func(ctx context.Context, id uuid.UUID) (*ProtectedFile, error)
	restoreProtectedFileFn func(ctx context.Context, protectedFileID uuid.UUID, organizationID uuid.UUID, req *RestoreProtectedFileRequest) (*RestoreProtectedFileResponse, error)
}

func (f *fakeProtectedFileService) RegisterProtectedFile(ctx context.Context, req *RegisterProtectedFileRequest) (*RegisterProtectedFileResponse, error) {
	return nil, errors.New("register protected file is not implemented by fakeProtectedFileService")
}

func (f *fakeProtectedFileService) GetProtectedFile(ctx context.Context, protectedFileID uuid.UUID) (*ProtectedFile, error) {
	return f.getProtectedFileFn(ctx, protectedFileID)
}

func (f *fakeProtectedFileService) RestoreProtectedFile(ctx context.Context, protectedFileID uuid.UUID, organizationID uuid.UUID, req *RestoreProtectedFileRequest) (*RestoreProtectedFileResponse, error) {
	return f.restoreProtectedFileFn(ctx, protectedFileID, organizationID, req)
}

type fakeAuthRepo struct {
	findUserByIDFn                 func(ctx context.Context, userID uuid.UUID) (*auth.User, error)
	createMFAChallengeFn           func(ctx context.Context, userID, organizationID uuid.UUID, emailHash, smsHash string, expiresAt time.Time) (uuid.UUID, error)
	cancelMFAChallengeFn           func(ctx context.Context, id uuid.UUID) error
	verifyAndConsumeMFAChallengeFn func(ctx context.Context, id uuid.UUID, emailCode, smsCode string) (*auth.MFAChallenge, error)
}

func (f *fakeAuthRepo) FindUserByID(ctx context.Context, userID uuid.UUID) (*auth.User, error) {
	return f.findUserByIDFn(ctx, userID)
}

func (f *fakeAuthRepo) IsDeviceTrusted(ctx context.Context, user, org uuid.UUID, device string) (bool, error) {
	return true, nil
}

func (f *fakeAuthRepo) CreateMFAChallenge(ctx context.Context, userID, organizationID uuid.UUID, emailHash, smsHash string, expiresAt time.Time) (uuid.UUID, error) {
	return f.createMFAChallengeFn(ctx, userID, organizationID, emailHash, smsHash, expiresAt)
}

func (f *fakeAuthRepo) CancelMFAChallenge(ctx context.Context, id uuid.UUID) error {
	return f.cancelMFAChallengeFn(ctx, id)
}

func (f *fakeAuthRepo) VerifyAndConsumeMFAChallenge(ctx context.Context, id uuid.UUID, emailCode, smsCode string) (*auth.MFAChallenge, error) {
	return f.verifyAndConsumeMFAChallengeFn(ctx, id, emailCode, smsCode)
}

type fakeMFAOTPDelivery struct {
	deliveredTo   string
	deliveredCode string
	error         error
}

func (f *fakeMFAOTPDelivery) DeliverMFAOTP(ctx context.Context, emailAddress, emailCode string) error {
	f.deliveredTo = emailAddress
	f.deliveredCode = emailCode
	return f.error
}

func setupGinContext(t *testing.T, method, path string, body []byte) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(recorder)
	c.Request = req
	return c, recorder
}

func TestStartOwnerProtectedFileRestore_ReturnsAcceptedAndCreatesChallenge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	organizationID := uuid.New()
	ownerUserID := uuid.New()
	protectedFileID := uuid.New()

	service := &fakeProtectedFileService{
		getProtectedFileFn: func(ctx context.Context, id uuid.UUID) (*ProtectedFile, error) {
			require.Equal(t, protectedFileID, id)
			return &ProtectedFile{
				ID:             protectedFileID,
				OrganizationID: organizationID,
				OwnerUserID:    ownerUserID,
			}, nil
		},
	}

	challengeID := uuid.New()
	authRepo := &fakeAuthRepo{
		findUserByIDFn: func(ctx context.Context, userID uuid.UUID) (*auth.User, error) {
			require.Equal(t, ownerUserID, userID)
			return &auth.User{
				ID:             ownerUserID,
				OrganizationID: organizationID,
				OfficialEmail:  "owner@example.com",
				EmailVerified:  true,
				PasswordHash:   "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
			}, nil
		},
		createMFAChallengeFn: func(ctx context.Context, userID, orgID uuid.UUID, emailHash, smsHash string, expiresAt time.Time) (uuid.UUID, error) {
			require.Equal(t, ownerUserID, userID)
			require.Equal(t, organizationID, orgID)
			require.NotEmpty(t, emailHash)
			require.NotEmpty(t, smsHash)
			require.WithinDuration(t, time.Now().UTC().Add(10*time.Minute), expiresAt, 30*time.Second)
			return challengeID, nil
		},
		cancelMFAChallengeFn: func(ctx context.Context, id uuid.UUID) error {
			t.Fatal("cancel should not be called")
			return nil
		},
	}

	mfaDelivery := &fakeMFAOTPDelivery{}
	handler := NewHandler(service, authRepo, mfaDelivery)

	c, recorder := setupGinContext(t, http.MethodPost, "/protected-files/"+protectedFileID.String()+"/restore/owner/start", nil)
	c.Set("organization_id", organizationID)
	c.Set("user_id", ownerUserID)
	c.Params = gin.Params{{Key: "id", Value: protectedFileID.String()}}

	handler.StartOwnerProtectedFileRestore(c)

	require.Equal(t, http.StatusAccepted, recorder.Code)

	var response struct {
		Success bool `json:"success"`
		Data    struct {
			MFAChallengeID   string `json:"mfa_challenge_id"`
			ExpiresInSeconds int64  `json:"expires_in_seconds"`
		} `json:"data"`
	}
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err)
	require.True(t, response.Success)
	require.Equal(t, challengeID.String(), response.Data.MFAChallengeID)
	require.NotZero(t, response.Data.ExpiresInSeconds)
	require.Equal(t, "owner@example.com", mfaDelivery.deliveredTo)
	require.Len(t, mfaDelivery.deliveredCode, 6)
}

func TestRestoreProtectedFileOwner_ReturnsOKAfterVerifyAndRestore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	organizationID := uuid.New()
	ownerUserID := uuid.New()
	protectedFileID := uuid.New()

	result := &RestoreProtectedFileResponse{
		ProtectedFileID:   protectedFileID.String(),
		RestoredFileName:  "example.txt",
		FileSizeBytes:     1024,
		IntegrityVerified: true,
		RestoredAt:        time.Now().UTC().Format(time.RFC3339),
	}

	service := &fakeProtectedFileService{
		getProtectedFileFn: func(ctx context.Context, id uuid.UUID) (*ProtectedFile, error) {
			require.Equal(t, protectedFileID, id)
			return &ProtectedFile{
				ID:             protectedFileID,
				OrganizationID: organizationID,
				OwnerUserID:    ownerUserID,
			}, nil
		},
		restoreProtectedFileFn: func(ctx context.Context, protectedFileIDArg uuid.UUID, organizationIDArg uuid.UUID, req *RestoreProtectedFileRequest) (*RestoreProtectedFileResponse, error) {
			require.Equal(t, protectedFileID, protectedFileIDArg)
			require.Equal(t, organizationID, organizationIDArg)
			require.Equal(t, "restoring file", req.RestoreReason)
			return result, nil
		},
	}

	challengeID := uuid.New()
	authRepo := &fakeAuthRepo{
		findUserByIDFn: func(ctx context.Context, userID uuid.UUID) (*auth.User, error) {
			require.Equal(t, ownerUserID, userID)
			return &auth.User{
				ID:             ownerUserID,
				OrganizationID: organizationID,
				OfficialEmail:  "owner@example.com",
				EmailVerified:  true,
			}, nil
		},
		verifyAndConsumeMFAChallengeFn: func(ctx context.Context, id uuid.UUID, emailCode, smsCode string) (*auth.MFAChallenge, error) {
			require.Equal(t, challengeID, id)
			require.Equal(t, "123456", emailCode)
			require.Equal(t, "123456", smsCode)
			return &auth.MFAChallenge{
				ID:             challengeID,
				UserID:         ownerUserID,
				OrganizationID: organizationID,
			}, nil
		},
	}

	mfaDelivery := &fakeMFAOTPDelivery{}
	handler := NewHandler(service, authRepo, mfaDelivery)

	requestBody, err := json.Marshal(map[string]string{
		"restore_reason":   "restoring file",
		"mfa_challenge_id": challengeID.String(),
		"email_code":       "123456",
		"password":         "password",
		"device_id":        "trusted-device-01",
	})
	require.NoError(t, err)

	c, recorder := setupGinContext(t, http.MethodPost, "/protected-files/"+protectedFileID.String()+"/restore/owner", requestBody)
	c.Set("organization_id", organizationID)
	c.Set("user_id", ownerUserID)
	c.Params = gin.Params{{Key: "id", Value: protectedFileID.String()}}

	handler.RestoreProtectedFileOwner(c)

	require.Equal(t, http.StatusOK, recorder.Code)

	var response struct {
		Success bool                         `json:"success"`
		Data    RestoreProtectedFileResponse `json:"data"`
	}
	err = json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err)
	require.True(t, response.Success)
	require.Equal(t, result, &response.Data)
}
