package honeytoken

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrFileDecryptionServiceUnavailable = errors.New(
		"file decryption service is unavailable",
	)
	ErrProtectedPackageNotFound = errors.New(
		"protected package not found",
	)
	ErrInvalidProtectedPackage = errors.New(
		"protected package is invalid or corrupted",
	)
	ErrProtectedPackageAuthenticationFailed = errors.New(
		"protected package authentication failed",
	)
	ErrDecryptedFileIntegrityCheckFailed = errors.New(
		"decrypted file integrity verification failed",
	)
	ErrRestoreTargetAlreadyExists = errors.New(
		"restore target already exists",
	)
)

// FileDecryptionService validates and decrypts Digital Defense Hub
// protected packages created by FileProtectionService.
type FileDecryptionService struct {
	encryptionKey   []byte
	encryptionKeyID string
}

// NewFileDecryptionService creates the protected-file decryption engine.
func NewFileDecryptionService(
	encryptionKey []byte,
	encryptionKeyID string,
) (*FileDecryptionService, error) {
	if len(encryptionKey) != aes256KeySize {
		return nil, ErrInvalidEncryptionKey
	}

	encryptionKeyID = strings.TrimSpace(
		encryptionKeyID,
	)
	if encryptionKeyID == "" {
		return nil, fmt.Errorf(
			"encryption key ID is required",
		)
	}

	keyCopy := make(
		[]byte,
		len(encryptionKey),
	)
	copy(
		keyCopy,
		encryptionKey,
	)

	return &FileDecryptionService{
		encryptionKey:   keyCopy,
		encryptionKeyID: encryptionKeyID,
	}, nil
}

// FileDecryptionInput contains the trusted database metadata required
// to restore one protected package.
type FileDecryptionInput struct {
	ProtectedFilePath string
	OutputDirectory   string
	OriginalFileName  string

	ExpectedSHA256Hash string
	EncryptionKeyID    string
}

// FileDecryptionResult describes the successfully restored original file.
type FileDecryptionResult struct {
	RestoredFileName string
	RestoredFilePath string

	FileSizeBytes int64
	SHA256Hash    string

	EncryptionKeyID string
	RestoredAt      time.Time
}

// DecryptFile authenticates and decrypts a .ddh package, verifies the
// original SHA-256 hash and writes the restored file without overwriting
// any existing file.
func (s *FileDecryptionService) DecryptFile(
	ctx context.Context,
	input FileDecryptionInput,
) (*FileDecryptionResult, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}

	if err := validateFileDecryptionContext(ctx); err != nil {
		return nil, err
	}

	validatedInput, expectedHash, err := validateFileDecryptionInput(
		input,
		s.encryptionKeyID,
	)
	if err != nil {
		return nil, err
	}

	packageInfo, err := os.Stat(
		validatedInput.ProtectedFilePath,
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrProtectedPackageNotFound
		}

		return nil, fmt.Errorf(
			"failed to inspect protected package: %w",
			err,
		)
	}

	if !packageInfo.Mode().IsRegular() {
		return nil, ErrInvalidProtectedPackage
	}

	protectedPackage, err := os.ReadFile(
		validatedInput.ProtectedFilePath,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to read protected package: %w",
			err,
		)
	}
	defer clear(protectedPackage)

	if err := validateFileDecryptionContext(ctx); err != nil {
		return nil, err
	}

	plainData, err := s.decryptPackage(
		protectedPackage,
	)
	if err != nil {
		return nil, err
	}
	defer clear(plainData)

	if err := validateFileDecryptionContext(ctx); err != nil {
		return nil, err
	}

	calculatedHash := sha256.Sum256(
		plainData,
	)

	if subtle.ConstantTimeCompare(
		calculatedHash[:],
		expectedHash,
	) != 1 {
		return nil, ErrDecryptedFileIntegrityCheckFailed
	}

	if err := os.MkdirAll(
		validatedInput.OutputDirectory,
		0700,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to create restore directory: %w",
			err,
		)
	}

	restoredFilePath := filepath.Join(
		validatedInput.OutputDirectory,
		validatedInput.OriginalFileName,
	)

	if err := writeNewFileAtomically(
		restoredFilePath,
		plainData,
		0600,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to write restored file: %w",
			err,
		)
	}

	restoredAt := time.Now().UTC()

	return &FileDecryptionResult{
		RestoredFileName: validatedInput.OriginalFileName,
		RestoredFilePath: restoredFilePath,

		FileSizeBytes: int64(len(plainData)),
		SHA256Hash: hex.EncodeToString(
			calculatedHash[:],
		),

		EncryptionKeyID: s.encryptionKeyID,
		RestoredAt:      restoredAt,
	}, nil
}

func (s *FileDecryptionService) validate() error {
	if s == nil {
		return ErrFileDecryptionServiceUnavailable
	}

	if len(s.encryptionKey) != aes256KeySize {
		return ErrInvalidEncryptionKey
	}

	if strings.TrimSpace(s.encryptionKeyID) == "" {
		return fmt.Errorf(
			"file decryption encryption key ID is required",
		)
	}

	return nil
}

func validateFileDecryptionContext(
	ctx context.Context,
) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"request context is not active: %w",
			err,
		)
	}

	return nil
}

func validateFileDecryptionInput(
	input FileDecryptionInput,
	serviceEncryptionKeyID string,
) (FileDecryptionInput, []byte, error) {
	input.ProtectedFilePath = strings.TrimSpace(
		input.ProtectedFilePath,
	)
	if input.ProtectedFilePath == "" {
		return FileDecryptionInput{}, nil, fmt.Errorf(
			"protected file path is required",
		)
	}

	if !strings.EqualFold(
		filepath.Ext(input.ProtectedFilePath),
		protectedPackageExtension,
	) {
		return FileDecryptionInput{}, nil, fmt.Errorf(
			"protected file must use the %s extension",
			protectedPackageExtension,
		)
	}

	input.OutputDirectory = strings.TrimSpace(
		input.OutputDirectory,
	)
	if input.OutputDirectory == "" {
		return FileDecryptionInput{}, nil, fmt.Errorf(
			"output directory is required",
		)
	}

	input.OriginalFileName = strings.TrimSpace(
		input.OriginalFileName,
	)
	if err := validateRestoreFileName(
		input.OriginalFileName,
	); err != nil {
		return FileDecryptionInput{}, nil, err
	}

	input.EncryptionKeyID = strings.TrimSpace(
		input.EncryptionKeyID,
	)
	if input.EncryptionKeyID == "" {
		return FileDecryptionInput{}, nil, fmt.Errorf(
			"encryption key ID is required",
		)
	}

	if input.EncryptionKeyID != serviceEncryptionKeyID {
		return FileDecryptionInput{}, nil, fmt.Errorf(
			"encryption key ID does not match the protected file",
		)
	}

	normalizedHash := strings.ToLower(
		strings.TrimSpace(input.ExpectedSHA256Hash),
	)
	if len(normalizedHash) != sha256.Size*2 {
		return FileDecryptionInput{}, nil, fmt.Errorf(
			"expected SHA-256 hash must contain exactly %d hexadecimal characters",
			sha256.Size*2,
		)
	}

	expectedHash, err := hex.DecodeString(
		normalizedHash,
	)
	if err != nil {
		return FileDecryptionInput{}, nil, fmt.Errorf(
			"expected SHA-256 hash is invalid: %w",
			err,
		)
	}

	input.ExpectedSHA256Hash = normalizedHash

	return input, expectedHash, nil
}

func validateRestoreFileName(
	fileName string,
) error {
	if fileName == "" {
		return fmt.Errorf(
			"original file name is required",
		)
	}

	if fileName == "." || fileName == ".." {
		return fmt.Errorf(
			"original file name is invalid",
		)
	}

	if filepath.IsAbs(fileName) ||
		filepath.Base(fileName) != fileName ||
		strings.ContainsAny(fileName, `/\:`) ||
		strings.ContainsRune(fileName, '\x00') {
		return fmt.Errorf(
			"original file name must not contain a path",
		)
	}

	if strings.HasSuffix(fileName, ".") ||
		strings.HasSuffix(fileName, " ") {
		return fmt.Errorf(
			"original file name must not end with a dot or space",
		)
	}

	if isWindowsReservedFileName(fileName) {
		return fmt.Errorf(
			"original file name is reserved by the operating system",
		)
	}

	return nil
}

func isWindowsReservedFileName(
	fileName string,
) bool {
	baseName := strings.ToUpper(
		strings.TrimSuffix(
			fileName,
			filepath.Ext(fileName),
		),
	)

	switch baseName {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}

	if len(baseName) == 4 {
		prefix := baseName[:3]
		number := baseName[3]

		if (prefix == "COM" || prefix == "LPT") &&
			number >= '1' &&
			number <= '9' {
			return true
		}
	}

	return false
}

func (s *FileDecryptionService) decryptPackage(
	protectedPackage []byte,
) ([]byte, error) {
	block, err := aes.NewCipher(
		s.encryptionKey,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize AES cipher: %w",
			err,
		)
	}

	gcm, err := cipher.NewGCM(
		block,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to initialize AES-GCM: %w",
			err,
		)
	}

	headerSize := len(
		protectedPackageMagicHeader,
	)
	minimumPackageSize := headerSize +
		gcm.NonceSize() +
		gcm.Overhead()

	if len(protectedPackage) < minimumPackageSize {
		return nil, ErrInvalidProtectedPackage
	}

	if !bytes.Equal(
		protectedPackage[:headerSize],
		[]byte(protectedPackageMagicHeader),
	) {
		return nil, ErrInvalidProtectedPackage
	}

	nonceStart := headerSize
	nonceEnd := nonceStart + gcm.NonceSize()

	nonce := protectedPackage[nonceStart:nonceEnd]
	cipherText := protectedPackage[nonceEnd:]

	plainData, err := gcm.Open(
		nil,
		nonce,
		cipherText,
		nil,
	)
	if err != nil {
		return nil, ErrProtectedPackageAuthenticationFailed
	}

	return plainData, nil
}

// writeNewFileAtomically prevents partial restores and refuses to
// replace a file that already exists.
func writeNewFileAtomically(
	targetPath string,
	data []byte,
	permission os.FileMode,
) error {
	directory := filepath.Dir(
		targetPath,
	)

	if _, err := os.Lstat(targetPath); err == nil {
		return ErrRestoreTargetAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"failed to inspect restore target: %w",
			err,
		)
	}

	tempFile, err := os.CreateTemp(
		directory,
		".ddh-restore-*",
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create restore temporary file: %w",
			err,
		)
	}

	tempPath := tempFile.Name()
	tempFileClosed := false

	defer func() {
		if !tempFileClosed {
			_ = tempFile.Close()
		}

		_ = os.Remove(tempPath)
	}()

	if err := tempFile.Chmod(
		permission,
	); err != nil {
		return fmt.Errorf(
			"failed to set restore file permission: %w",
			err,
		)
	}

	if _, err := io.Copy(
		tempFile,
		bytes.NewReader(data),
	); err != nil {
		return fmt.Errorf(
			"failed to write restore temporary file: %w",
			err,
		)
	}

	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf(
			"failed to synchronize restore temporary file: %w",
			err,
		)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf(
			"failed to close restore temporary file: %w",
			err,
		)
	}
	tempFileClosed = true

	if err := os.Link(
		tempPath,
		targetPath,
	); err != nil {
		if _, inspectionErr := os.Lstat(targetPath); inspectionErr == nil {
			return ErrRestoreTargetAlreadyExists
		}

		return fmt.Errorf(
			"failed to publish restored file: %w",
			err,
		)
	}

	if err := os.Remove(tempPath); err != nil {
		return fmt.Errorf(
			"restored file was created but temporary file cleanup failed: %w",
			err,
		)
	}

	return nil
}
