package deepfakeforensics

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestEncryptedMediaStorageRoundTrip(
	t *testing.T,
) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x42}, 32)
	manager, err := NewSecureAssetFileManager(
		t.TempDir(),
		1024*1024,
		AssetStorageOptions{
			EncryptionEnabled: true,
			EncryptionKeyBase64: base64.StdEncoding.EncodeToString(
				key,
			),
			QuarantineMalformed: true,
		},
	)
	if err != nil {
		t.Fatalf("create secure storage: %v", err)
	}

	content := append(
		append(
			[]byte(nil),
			pngSignature...,
		),
		bytes.Repeat([]byte("forensic-test"), 64)...,
	)
	organizationID := uuid.New()
	stored, err := manager.Store(
		context.Background(),
		organizationID,
		"sample.png",
		"image/png",
		bytes.NewReader(content),
	)
	if err != nil {
		t.Fatalf("store encrypted media: %v", err)
	}
	if !stored.IsEncrypted ||
		stored.EncryptionAlgorithm == nil {
		t.Fatal("expected encrypted stored media")
	}

	diskBytes, err := os.ReadFile(
		stored.StoragePath,
	)
	if err != nil {
		t.Fatalf("read encrypted media: %v", err)
	}
	if bytes.Contains(diskBytes, content) {
		t.Fatal("encrypted file contains plaintext payload")
	}

	extension := stored.FileExtension
	asset := MediaAnalysisAsset{
		ID:                  uuid.New(),
		OrganizationID:      organizationID,
		StoragePath:         stored.StoragePath,
		FileExtension:       &extension,
		FileSizeBytes:       stored.FileSizeBytes,
		FileHash:            stored.FileHash,
		IsEncrypted:         stored.IsEncrypted,
		EncryptionAlgorithm: stored.EncryptionAlgorithm,
	}

	prepared, err := manager.PrepareAnalysisSource(
		context.Background(),
		asset,
		uuid.New(),
	)
	if err != nil {
		t.Fatalf("prepare encrypted media: %v", err)
	}
	defer prepared.Cleanup()

	plaintext, err := os.ReadFile(prepared.Path)
	if err != nil {
		t.Fatalf("read prepared media: %v", err)
	}
	if !bytes.Equal(plaintext, content) {
		t.Fatal("decrypted media differs from uploaded content")
	}
}

func TestMalformedUploadIsQuarantined(
	t *testing.T,
) {
	t.Parallel()

	manager, err := NewSecureAssetFileManager(
		t.TempDir(),
		1024*1024,
		AssetStorageOptions{
			QuarantineMalformed: true,
		},
	)
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}

	stored, err := manager.Store(
		context.Background(),
		uuid.New(),
		"disguised.png",
		"image/png",
		bytes.NewReader(
			[]byte("MZ-not-an-image"),
		),
	)
	if !errors.Is(
		err,
		ErrMediaUploadQuarantined,
	) {
		t.Fatalf("expected quarantine error, got %v", err)
	}
	if stored == nil ||
		stored.Status !=
			mediaAssetStatusQuarantined {
		t.Fatal("expected quarantined stored file")
	}
	if !strings.Contains(
		stored.StoragePath,
		"_quarantine",
	) {
		t.Fatalf(
			"unexpected quarantine path: %s",
			stored.StoragePath,
		)
	}
}

func TestEncryptedMediaTamperingIsRejected(
	t *testing.T,
) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x31}, 32)
	manager, err := NewSecureAssetFileManager(
		t.TempDir(),
		1024*1024,
		AssetStorageOptions{
			EncryptionEnabled: true,
			EncryptionKeyBase64: base64.StdEncoding.EncodeToString(
				key,
			),
			QuarantineMalformed: true,
		},
	)
	if err != nil {
		t.Fatalf("create secure storage: %v", err)
	}

	content := append(
		append(
			[]byte(nil),
			pngSignature...,
		),
		bytes.Repeat([]byte("tamper-test"), 64)...,
	)
	organizationID := uuid.New()
	stored, err := manager.Store(
		context.Background(),
		organizationID,
		"tamper.png",
		"image/png",
		bytes.NewReader(content),
	)
	if err != nil {
		t.Fatalf("store encrypted media: %v", err)
	}

	encryptedBytes, err := os.ReadFile(
		stored.StoragePath,
	)
	if err != nil {
		t.Fatalf("read encrypted media: %v", err)
	}
	tamperOffset := len(mediaEncryptedHeader) +
		16 +
		1
	encryptedBytes[tamperOffset] ^= 0xff
	if err = os.WriteFile(
		stored.StoragePath,
		encryptedBytes,
		0o600,
	); err != nil {
		t.Fatalf("tamper encrypted media: %v", err)
	}

	extension := stored.FileExtension
	asset := MediaAnalysisAsset{
		ID:                  uuid.New(),
		OrganizationID:      organizationID,
		StoragePath:         stored.StoragePath,
		FileExtension:       &extension,
		FileSizeBytes:       stored.FileSizeBytes,
		FileHash:            stored.FileHash,
		IsEncrypted:         true,
		EncryptionAlgorithm: stored.EncryptionAlgorithm,
	}

	_, err = manager.PrepareAnalysisSource(
		context.Background(),
		asset,
		uuid.New(),
	)
	if !errors.Is(
		err,
		ErrMediaStorageIntegrity,
	) {
		t.Fatalf(
			"expected storage integrity error, got %v",
			err,
		)
	}
}

func TestExpectedMediaSignatures(
	t *testing.T,
) {
	t.Parallel()

	testCases := []struct {
		extension string
		header    []byte
	}{
		{".jpg", []byte{0xff, 0xd8, 0xff}},
		{".png", pngSignature},
		{".webp", []byte("RIFF0000WEBP")},
		{".mp4", []byte{0, 0, 0, 12, 'f', 't', 'y', 'p', 0, 0, 0, 0}},
		{".mkv", ebmlSignature},
		{".wav", []byte("RIFF0000WAVE")},
		{".mp3", []byte("ID3")},
		{".flac", []byte("fLaC")},
		{".ogg", []byte("OggS")},
		{".pdf", []byte("%PDF-1.7")},
	}

	for _, testCase := range testCases {
		if !matchesExpectedMediaSignature(
			testCase.extension,
			testCase.header,
		) {
			t.Fatalf(
				"signature rejected for %s",
				testCase.extension,
			)
		}
	}
}
