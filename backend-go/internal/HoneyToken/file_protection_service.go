package honeytoken

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	protectedPackageMagicHeader = "DDH1"
	protectedPackageExtension   = ".ddh"
	metadataFileExtension       = ".xml"
	aes256KeySize               = 32
)

var (
	ErrInvalidEncryptionKey = errors.New(
		"AES-256 encryption key must contain exactly 32 bytes",
	)
	ErrSourceFileNotFound = errors.New(
		"source file not found",
	)
	ErrInvalidSourceFile = errors.New(
		"source path must point to a regular file",
	)
)

// FileProtectionService handles hashing, encryption,
// protected package generation and XML metadata creation.
type FileProtectionService struct {
	encryptionKey   []byte
	encryptionKeyID string
}

// NewFileProtectionService creates the file protection engine.
func NewFileProtectionService(
	encryptionKey []byte,
	encryptionKeyID string,
) (*FileProtectionService, error) {
	if len(encryptionKey) != aes256KeySize {
		return nil, ErrInvalidEncryptionKey
	}

	if strings.TrimSpace(encryptionKeyID) == "" {
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

	return &FileProtectionService{
		encryptionKey:   keyCopy,
		encryptionKeyID: encryptionKeyID,
	}, nil
}

// FileProtectionInput contains the information required
// to protect one original file.
type FileProtectionInput struct {
	ProtectedFileID uuid.UUID
	OrganizationID  uuid.UUID
	DepartmentID    *uuid.UUID
	OwnerUserID     uuid.UUID

	SourceFilePath  string
	OutputDirectory string

	Category        string
	Sensitivity     string
	Classification  string
	RetentionPolicy string
	RetentionUntil  *time.Time
}

// FileProtectionResult contains generated file information.
type FileProtectionResult struct {
	OriginalFileName  string
	OriginalExtension string
	OriginalFilePath  string

	ProtectedFileName string
	ProtectedFilePath string

	MetadataFileName string
	MetadataFilePath string

	FileSizeBytes int64
	MimeType      string
	SHA256Hash    string

	EncryptionAlgorithm string
	EncryptionKeyID     string

	ProtectedAt time.Time
}

// protectedFileMetadata defines the XML metadata structure.
//
// The encryption key itself is never stored inside this XML file.
type protectedFileMetadata struct {
	XMLName xml.Name `xml:"digitalDefenseMetadata"`

	Version string `xml:"version,attr"`

	ProtectedFileID string `xml:"protectedFileId"`
	OrganizationID  string `xml:"organizationId"`
	DepartmentID    string `xml:"departmentId,omitempty"`
	OwnerUserID     string `xml:"ownerUserId"`

	OriginalFileName  string `xml:"originalFileName"`
	OriginalExtension string `xml:"originalExtension"`
	ProtectedFileName string `xml:"protectedFileName"`

	FileSizeBytes int64  `xml:"fileSizeBytes"`
	MimeType      string `xml:"mimeType"`
	SHA256Hash    string `xml:"sha256Hash"`

	EncryptionAlgorithm string `xml:"encryptionAlgorithm"`
	EncryptionKeyID     string `xml:"encryptionKeyId"`

	Category       string `xml:"category"`
	Sensitivity    string `xml:"sensitivity"`
	Classification string `xml:"classification"`

	RetentionPolicy string `xml:"retentionPolicy,omitempty"`
	RetentionUntil  string `xml:"retentionUntil,omitempty"`

	ProtectedAt string `xml:"protectedAt"`
}

// ProtectFile creates the encrypted .ddh package
// and its corresponding XML metadata file.
func (s *FileProtectionService) ProtectFile(
	ctx context.Context,
	input FileProtectionInput,
) (*FileProtectionResult, error) {
	if err := validateFileProtectionInput(input); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	sourceInfo, err := os.Stat(
		input.SourceFilePath,
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrSourceFileNotFound
		}

		return nil, fmt.Errorf(
			"failed to inspect source file: %w",
			err,
		)
	}

	if !sourceInfo.Mode().IsRegular() {
		return nil, ErrInvalidSourceFile
	}

	plainData, err := os.ReadFile(
		input.SourceFilePath,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to read source file: %w",
			err,
		)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	hashValue := sha256.Sum256(
		plainData,
	)

	sha256Hash := hex.EncodeToString(
		hashValue[:],
	)

	mimeType := detectFileMimeType(
		plainData,
		input.SourceFilePath,
	)

	encryptedPackage, err := s.encryptFileData(
		plainData,
	)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(
		input.OutputDirectory,
		0700,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to create output directory: %w",
			err,
		)
	}

	protectedAt := time.Now().UTC()

	protectedFileName := input.ProtectedFileID.String() +
		protectedPackageExtension

	metadataFileName := input.ProtectedFileID.String() +
		metadataFileExtension

	protectedFilePath := filepath.Join(
		input.OutputDirectory,
		protectedFileName,
	)

	metadataFilePath := filepath.Join(
		input.OutputDirectory,
		metadataFileName,
	)

	if err := writeFileAtomically(
		protectedFilePath,
		encryptedPackage,
		0600,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to write protected package: %w",
			err,
		)
	}

	metadata := buildProtectedFileMetadata(
		input,
		sourceInfo,
		protectedFileName,
		mimeType,
		sha256Hash,
		s.encryptionKeyID,
		protectedAt,
	)

	metadataData, err := xml.MarshalIndent(
		metadata,
		"",
		"    ",
	)
	if err != nil {
		_ = os.Remove(protectedFilePath)

		return nil, fmt.Errorf(
			"failed to generate XML metadata: %w",
			err,
		)
	}

	xmlHeader := []byte(
		xml.Header,
	)

	metadataData = append(
		xmlHeader,
		metadataData...,
	)

	if err := writeFileAtomically(
		metadataFilePath,
		metadataData,
		0600,
	); err != nil {
		_ = os.Remove(protectedFilePath)

		return nil, fmt.Errorf(
			"failed to write XML metadata: %w",
			err,
		)
	}

	return &FileProtectionResult{
		OriginalFileName: sourceInfo.Name(),
		OriginalExtension: strings.ToLower(
			filepath.Ext(sourceInfo.Name()),
		),
		OriginalFilePath: input.SourceFilePath,

		ProtectedFileName: protectedFileName,
		ProtectedFilePath: protectedFilePath,

		MetadataFileName: metadataFileName,
		MetadataFilePath: metadataFilePath,

		FileSizeBytes: sourceInfo.Size(),
		MimeType:      mimeType,
		SHA256Hash:    sha256Hash,

		EncryptionAlgorithm: "AES-256-GCM",
		EncryptionKeyID:     s.encryptionKeyID,

		ProtectedAt: protectedAt,
	}, nil
}

func validateFileProtectionInput(
	input FileProtectionInput,
) error {
	if input.ProtectedFileID == uuid.Nil {
		return fmt.Errorf(
			"protected file ID is required",
		)
	}

	if input.OrganizationID == uuid.Nil {
		return fmt.Errorf(
			"organization ID is required",
		)
	}

	if input.OwnerUserID == uuid.Nil {
		return fmt.Errorf(
			"owner user ID is required",
		)
	}

	if strings.TrimSpace(input.SourceFilePath) == "" {
		return fmt.Errorf(
			"source file path is required",
		)
	}

	if strings.TrimSpace(input.OutputDirectory) == "" {
		return fmt.Errorf(
			"output directory is required",
		)
	}

	return nil
}

// encryptFileData encrypts the original content using AES-256-GCM.
//
// Protected package layout:
//
// DDH1 header
// AES-GCM nonce
// Encrypted ciphertext
func (s *FileProtectionService) encryptFileData(
	plainData []byte,
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

	nonce := make(
		[]byte,
		gcm.NonceSize(),
	)

	if _, err := io.ReadFull(
		rand.Reader,
		nonce,
	); err != nil {
		return nil, fmt.Errorf(
			"failed to generate encryption nonce: %w",
			err,
		)
	}

	cipherText := gcm.Seal(
		nil,
		nonce,
		plainData,
		nil,
	)

	protectedPackage := make(
		[]byte,
		0,
		len(protectedPackageMagicHeader)+
			len(nonce)+
			len(cipherText),
	)

	protectedPackage = append(
		protectedPackage,
		[]byte(protectedPackageMagicHeader)...,
	)

	protectedPackage = append(
		protectedPackage,
		nonce...,
	)

	protectedPackage = append(
		protectedPackage,
		cipherText...,
	)

	return protectedPackage, nil
}

func detectFileMimeType(
	data []byte,
	filePath string,
) string {
	detectionLength := len(data)

	if detectionLength > 512 {
		detectionLength = 512
	}

	if detectionLength > 0 {
		detectedType := http.DetectContentType(
			data[:detectionLength],
		)

		if detectedType != "application/octet-stream" {
			return detectedType
		}
	}

	extension := strings.ToLower(
		filepath.Ext(filePath),
	)

	if extension != "" {
		extensionType := mime.TypeByExtension(
			extension,
		)

		if extensionType != "" {
			return extensionType
		}
	}

	return "application/octet-stream"
}

func buildProtectedFileMetadata(
	input FileProtectionInput,
	sourceInfo os.FileInfo,
	protectedFileName string,
	mimeType string,
	sha256Hash string,
	encryptionKeyID string,
	protectedAt time.Time,
) protectedFileMetadata {
	departmentID := ""

	if input.DepartmentID != nil {
		departmentID = input.DepartmentID.String()
	}

	retentionUntil := ""

	if input.RetentionUntil != nil {
		retentionUntil = input.RetentionUntil.
			UTC().
			Format(time.RFC3339)
	}

	return protectedFileMetadata{
		Version: "1.0",

		ProtectedFileID: input.ProtectedFileID.String(),
		OrganizationID:  input.OrganizationID.String(),
		DepartmentID:    departmentID,
		OwnerUserID:     input.OwnerUserID.String(),

		OriginalFileName: sourceInfo.Name(),
		OriginalExtension: strings.ToLower(
			filepath.Ext(sourceInfo.Name()),
		),
		ProtectedFileName: protectedFileName,

		FileSizeBytes: sourceInfo.Size(),
		MimeType:      mimeType,
		SHA256Hash:    sha256Hash,

		EncryptionAlgorithm: "AES-256-GCM",
		EncryptionKeyID:     encryptionKeyID,

		Category:       input.Category,
		Sensitivity:    input.Sensitivity,
		Classification: input.Classification,

		RetentionPolicy: input.RetentionPolicy,
		RetentionUntil:  retentionUntil,

		ProtectedAt: protectedAt.Format(
			time.RFC3339,
		),
	}
}

// writeFileAtomically prevents partially written protected files.
func writeFileAtomically(
	targetPath string,
	data []byte,
	permission os.FileMode,
) error {
	directory := filepath.Dir(
		targetPath,
	)

	tempFile, err := os.CreateTemp(
		directory,
		".ddh-temp-*",
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create temporary file: %w",
			err,
		)
	}

	tempPath := tempFile.Name()

	defer func() {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
	}()

	if err := tempFile.Chmod(
		permission,
	); err != nil {
		return fmt.Errorf(
			"failed to set temporary file permission: %w",
			err,
		)
	}

	if _, err := tempFile.Write(
		data,
	); err != nil {
		return fmt.Errorf(
			"failed to write temporary file: %w",
			err,
		)
	}

	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf(
			"failed to synchronize temporary file: %w",
			err,
		)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf(
			"failed to close temporary file: %w",
			err,
		)
	}

	if err := os.Rename(
		tempPath,
		targetPath,
	); err != nil {
		return fmt.Errorf(
			"failed to move temporary file: %w",
			err,
		)
	}

	return nil
}
