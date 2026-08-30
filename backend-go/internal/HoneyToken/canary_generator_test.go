package honeytoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCanaryGeneratorImportCopiesSourceWithoutMutation(t *testing.T) {
	storageRoot := t.TempDir()
	generator, err := NewCanaryGenerator(storageRoot)
	require.NoError(t, err)

	sourceContent := []byte("confidential source record\naccount=12345\n")
	sourcePath := filepath.Join(t.TempDir(), "Finance_Report.txt")
	require.NoError(t, os.WriteFile(sourcePath, sourceContent, 0600))

	source, err := os.Open(sourcePath)
	require.NoError(t, err)

	result, err := generator.Import(
		context.Background(),
		canaryGenerationInput{
			ID:             uuid.New(),
			OrganizationID: uuid.New(),
			FileName:       "Finance_Report.txt",
			CanaryType:     CanaryTypeDocument,
		},
		source,
	)
	require.NoError(t, source.Close())
	require.NoError(t, err)

	stagedContent, err := os.ReadFile(result.FilePath)
	require.NoError(t, err)
	require.Equal(t, sourceContent, stagedContent)

	sourceAfterImport, err := os.ReadFile(sourcePath)
	require.NoError(t, err)
	require.Equal(t, sourceContent, sourceAfterImport)

	digest := sha256.Sum256(sourceContent)
	require.Equal(t, hex.EncodeToString(digest[:]), result.OriginalFileHash)
	require.Equal(t, int64(len(sourceContent)), result.FileSizeBytes)
	require.Equal(t, ".txt", result.FileExtension)
	require.Equal(t, "text/plain", result.MimeType)
	require.NotContains(t, string(stagedContent), result.TrackingIdentifier)
	require.True(t, isPathWithinCanaryRoot(storageRoot, result.FilePath))
}

func TestCanaryGeneratorImportRejectsOversizedFile(t *testing.T) {
	generator, err := NewCanaryGenerator(t.TempDir())
	require.NoError(t, err)

	_, err = generator.Import(
		context.Background(),
		canaryGenerationInput{
			ID:             uuid.New(),
			OrganizationID: uuid.New(),
			FileName:       "large.txt",
			CanaryType:     CanaryTypeDocument,
		},
		bytes.NewReader(make([]byte, MaxCanaryImportSize+1)),
	)
	require.ErrorIs(t, err, ErrCanaryImportTooLarge)
}

func TestCanaryGeneratorImportRejectsMismatchedSignature(t *testing.T) {
	generator, err := NewCanaryGenerator(t.TempDir())
	require.NoError(t, err)

	_, err = generator.Import(
		context.Background(),
		canaryGenerationInput{
			ID:             uuid.New(),
			OrganizationID: uuid.New(),
			FileName:       "report.pdf",
			CanaryType:     CanaryTypePDF,
		},
		bytes.NewReader([]byte("this is not a PDF")),
	)
	require.ErrorIs(t, err, ErrCanaryImportFormat)
}

func TestCanaryImportSupportsFrontendExtensionSet(t *testing.T) {
	testCases := []struct {
		fileName string
		content  []byte
	}{
		{fileName: "record.txt", content: []byte("record")},
		{fileName: "record.csv", content: []byte("name,value\nA,1\n")},
		{fileName: "record.pdf", content: []byte("%PDF-1.4\n%%EOF")},
		{fileName: "record.png", content: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}},
		{fileName: "record.jpg", content: []byte{0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xD9}},
		{fileName: "record.jpeg", content: []byte{0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xD9}},
		{fileName: "record.webp", content: []byte("RIFF0000WEBP")},
		{fileName: "backup.sql", content: []byte("SELECT 1;")},
		{fileName: "settings.ini", content: []byte("[app]\nsecure=true")},
		{fileName: "settings.conf", content: []byte("secure=true")},
		{fileName: "settings.cfg", content: []byte("secure=true")},
		{fileName: "record.json", content: []byte(`{"secure":true}`)},
		{fileName: "settings.yaml", content: []byte("secure: true")},
		{fileName: "settings.yml", content: []byte("secure: true")},
		{fileName: "main.go", content: []byte("package main")},
	}

	for _, testCase := range testCases {
		t.Run(testCase.fileName, func(t *testing.T) {
			canaryType, err := inferImportedCanaryType(testCase.fileName)
			require.NoError(t, err)

			extension := filepath.Ext(testCase.fileName)
			require.NoError(
				t,
				validateImportedCanaryContent(
					extension,
					canaryType,
					testCase.content,
				),
			)
		})
	}
}
