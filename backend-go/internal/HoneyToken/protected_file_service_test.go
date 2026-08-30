package honeytoken

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type fakeCanaryCreator struct {
	created        bool
	ctx            context.Context
	organizationID uuid.UUID
	createdBy      uuid.UUID
	request        CreateCanaryFileRequest
}

func (f *fakeCanaryCreator) CreateCanaryFile(
	ctx context.Context,
	organizationID uuid.UUID,
	createdBy uuid.UUID,
	request CreateCanaryFileRequest,
) (*CreateCanaryFileResponse, error) {
	f.created = true
	f.ctx = ctx
	f.organizationID = organizationID
	f.createdBy = createdBy
	f.request = request

	return &CreateCanaryFileResponse{
		ID:                 uuid.New(),
		CanaryCode:         "TEST-CODE",
		FileName:           request.FileName,
		CanaryType:         request.CanaryType,
		HashAlgorithm:      CanaryHashAlgorithmSHA256,
		ContainsHoneytoken: request.ContainsHoneytoken,
		Status:             CanaryStatusDraft,
		CreatedAt:          time.Now().UTC(),
	}, nil
}

func TestProtectedFileService_createAutoCanaryFile_CreatesCanaryFile(t *testing.T) {
	service := &Service{
		canaryService: &fakeCanaryCreator{},
	}

	organizationID := uuid.New()
	ownerUserID := uuid.New()

	file := &ProtectedFile{
		OrganizationID:   organizationID,
		OwnerUserID:      ownerUserID,
		OriginalFilePath: "/tmp/source-file.txt",
	}

	err := service.createAutoCanaryFile(context.Background(), file)
	require.NoError(t, err)

	creator := service.canaryService.(*fakeCanaryCreator)
	require.True(t, creator.created)
	require.Equal(t, organizationID, creator.organizationID)
	require.Equal(t, ownerUserID, creator.createdBy)
	require.Equal(t, "canary-source-file.txt", creator.request.FileName)
	require.Equal(t, CanaryTypeCustom, creator.request.CanaryType)
	require.Equal(t, ownerUserID.String(), *creator.request.OwnerUserID)
	require.False(t, creator.request.ContainsHoneytoken)
}
