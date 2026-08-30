package honeytoken

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCanaryServiceImportRejectsNilSourceBeforeRepositoryAccess(t *testing.T) {
	service := &CanaryService{}

	_, err := service.ImportCanaryFile(
		context.Background(),
		uuid.New(),
		uuid.New(),
		ImportCanaryFileRequest{},
		"record.txt",
		nil,
	)
	require.ErrorIs(t, err, ErrCanaryImportEmpty)
}

func TestCanaryServiceImportRejectsUnsupportedExtensionBeforeRepositoryAccess(t *testing.T) {
	service := &CanaryService{}

	_, err := service.ImportCanaryFile(
		context.Background(),
		uuid.New(),
		uuid.New(),
		ImportCanaryFileRequest{},
		"payload.exe",
		bytes.NewReader([]byte("not executable content")),
	)
	require.ErrorIs(t, err, ErrCanaryImportFormat)
}
