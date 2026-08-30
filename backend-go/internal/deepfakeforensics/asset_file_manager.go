package deepfakeforensics

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

const (
	defaultMaximumMediaUploadBytes int64 = 512 * 1024 * 1024

	mediaUploadBufferSize = 128 * 1024
)

var (
	ErrInvalidMediaUpload = errors.New(
		"invalid media analysis upload",
	)
	ErrMediaUploadTooLarge = errors.New(
		"media analysis upload exceeds the configured size limit",
	)
	ErrUnsupportedMediaUpload = errors.New(
		"unsupported media analysis file type",
	)
	ErrManagedMediaPathRequired = errors.New(
		"media file path is outside the managed storage root",
	)
	ErrMediaUploadQuarantined = errors.New(
		"media analysis upload was quarantined",
	)
	ErrMediaStorageIntegrity = errors.New(
		"media storage integrity verification failed",
	)
)

type mediaUploadType struct {
	MediaType string
	MimeType  string
}

const mediaStorageEncryptionAlgorithm = "AES-256-CTR-HMAC-SHA256"

var supportedMediaUploadTypes = map[string]mediaUploadType{
	".jpg": {
		MediaType: MediaTypeImage,
		MimeType:  "image/jpeg",
	},
	".jpeg": {
		MediaType: MediaTypeImage,
		MimeType:  "image/jpeg",
	},
	".png": {
		MediaType: MediaTypeImage,
		MimeType:  "image/png",
	},
	".webp": {
		MediaType: MediaTypeImage,
		MimeType:  "image/webp",
	},
	".bmp": {
		MediaType: MediaTypeImage,
		MimeType:  "image/bmp",
	},
	".tif": {
		MediaType: MediaTypeImage,
		MimeType:  "image/tiff",
	},
	".tiff": {
		MediaType: MediaTypeImage,
		MimeType:  "image/tiff",
	},
	".mp4": {
		MediaType: MediaTypeVideo,
		MimeType:  "video/mp4",
	},
	".mov": {
		MediaType: MediaTypeVideo,
		MimeType:  "video/quicktime",
	},
	".avi": {
		MediaType: MediaTypeVideo,
		MimeType:  "video/x-msvideo",
	},
	".mkv": {
		MediaType: MediaTypeVideo,
		MimeType:  "video/x-matroska",
	},
	".webm": {
		MediaType: MediaTypeVideo,
		MimeType:  "video/webm",
	},
	".m4v": {
		MediaType: MediaTypeVideo,
		MimeType:  "video/x-m4v",
	},
	".wav": {
		MediaType: MediaTypeAudio,
		MimeType:  "audio/wav",
	},
	".mp3": {
		MediaType: MediaTypeAudio,
		MimeType:  "audio/mpeg",
	},
	".flac": {
		MediaType: MediaTypeAudio,
		MimeType:  "audio/flac",
	},
	".m4a": {
		MediaType: MediaTypeAudio,
		MimeType:  "audio/mp4",
	},
	".aac": {
		MediaType: MediaTypeAudio,
		MimeType:  "audio/aac",
	},
	".ogg": {
		MediaType: MediaTypeAudio,
		MimeType:  "audio/ogg",
	},
	".pdf": {
		MediaType: MediaTypeDocument,
		MimeType:  "application/pdf",
	},
}

// StoredMediaFile contains the normalized metadata for one
// successfully persisted upload.
type StoredMediaFile struct {
	OriginalFileName string
	StoredFileName   string
	StoragePath      string

	MediaType     string
	MimeType      string
	FileExtension string

	FileSizeBytes  int64
	FileHash       string
	FileHashSHA512 string

	IsEncrypted         bool
	EncryptionAlgorithm *string
	Status              string
	QuarantineReason    string
}

// AssetStorageOptions enables encrypted-at-rest storage
// and automatic isolation of malformed uploads.
type AssetStorageOptions struct {
	EncryptionEnabled   bool
	EncryptionKeyBase64 string
	QuarantineMalformed bool
}

// AssetFileManager owns organization-isolated local media
// upload storage.
type AssetFileManager struct {
	rootPath       string
	runtimePath    string
	quarantinePath string
	maximumBytes   int64

	encryptionEnabled   bool
	encryptionKey       []byte
	quarantineMalformed bool
}

func NewAssetFileManager(
	rootPath string,
	maximumBytes int64,
) (*AssetFileManager, error) {
	return NewSecureAssetFileManager(
		rootPath,
		maximumBytes,
		AssetStorageOptions{},
	)
}

// NewSecureAssetFileManager creates an organization-isolated
// storage manager with optional authenticated encryption.
func NewSecureAssetFileManager(
	rootPath string,
	maximumBytes int64,
	options AssetStorageOptions,
) (*AssetFileManager, error) {
	rootPath = strings.TrimSpace(rootPath)
	if rootPath == "" {
		return nil, errors.New(
			"media analysis storage root is required",
		)
	}
	if maximumBytes <= 0 {
		maximumBytes =
			defaultMaximumMediaUploadBytes
	}

	var encryptionKey []byte
	if options.EncryptionEnabled {
		decodedKey, decodeErr :=
			base64.StdEncoding.DecodeString(
				strings.TrimSpace(
					options.EncryptionKeyBase64,
				),
			)
		if decodeErr != nil ||
			len(decodedKey) != 32 {
			return nil, errors.New(
				"media storage encryption key must be a base64-encoded 32-byte key",
			)
		}
		encryptionKey = decodedKey
	}

	absoluteRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve media analysis storage root: %w",
			err,
		)
	}
	absoluteRoot = filepath.Clean(
		absoluteRoot,
	)

	if err = os.MkdirAll(
		absoluteRoot,
		0o700,
	); err != nil {
		return nil, fmt.Errorf(
			"create media analysis storage root: %w",
			err,
		)
	}

	rootInformation, err := os.Lstat(
		absoluteRoot,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"inspect media analysis storage root: %w",
			err,
		)
	}
	if !rootInformation.IsDir() ||
		rootInformation.Mode()&
			os.ModeSymlink != 0 {
		return nil, errors.New(
			"media analysis storage root must be a real directory",
		)
	}

	manager := &AssetFileManager{
		rootPath:       absoluteRoot,
		runtimePath:    filepath.Join(absoluteRoot, "_runtime"),
		quarantinePath: filepath.Join(absoluteRoot, "_quarantine"),
		maximumBytes:   maximumBytes,

		encryptionEnabled: options.EncryptionEnabled,
		encryptionKey: append(
			[]byte(nil),
			encryptionKey...,
		),
		quarantineMalformed: options.QuarantineMalformed,
	}

	for _, directory := range []string{
		manager.runtimePath,
		manager.quarantinePath,
	} {
		if err = manager.ensureManagedDirectory(
			directory,
		); err != nil {
			return nil, fmt.Errorf(
				"initialize protected media storage directory: %w",
				err,
			)
		}
	}

	return manager, nil
}

// Store validates, hashes and atomically persists one
// uploaded file beneath its organization directory.
func (m *AssetFileManager) Store(
	ctx context.Context,
	organizationID uuid.UUID,
	originalFileName string,
	declaredMimeType string,
	source io.Reader,
) (*StoredMediaFile, error) {
	if m == nil ||
		strings.TrimSpace(m.rootPath) == "" ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		source == nil {
		return nil, ErrInvalidMediaUpload
	}

	normalizedFileName, extension,
		uploadType, err :=
		normalizeMediaUploadName(
			originalFileName,
		)
	if err != nil {
		return nil, err
	}

	bufferedSource := bufio.NewReaderSize(
		&mediaContextReader{
			ctx:    ctx,
			reader: source,
		},
		mediaUploadBufferSize,
	)

	header, peekErr := bufferedSource.Peek(512)
	if peekErr != nil &&
		!errors.Is(peekErr, io.EOF) &&
		!errors.Is(
			peekErr,
			bufio.ErrBufferFull,
		) {
		return nil, fmt.Errorf(
			"inspect media upload header: %w",
			peekErr,
		)
	}
	if len(header) == 0 {
		return nil, fmt.Errorf(
			"%w: uploaded file is empty",
			ErrInvalidMediaUpload,
		)
	}

	detectedMimeType := http.DetectContentType(
		header,
	)
	if err = validateMediaUploadMimeType(
		extension,
		uploadType,
		declaredMimeType,
		detectedMimeType,
		header,
	); err != nil {
		if m.quarantineMalformed {
			quarantinedFile, quarantineErr :=
				m.persistMediaStream(
					ctx,
					organizationID,
					normalizedFileName,
					extension,
					uploadType,
					bufferedSource,
					true,
					err.Error(),
				)
			if quarantineErr != nil {
				return nil, fmt.Errorf(
					"%w; quarantine failed: %v",
					err,
					quarantineErr,
				)
			}

			return quarantinedFile,
				fmt.Errorf(
					"%w: %v",
					ErrMediaUploadQuarantined,
					err,
				)
		}

		return nil, err
	}

	return m.persistMediaStream(
		ctx,
		organizationID,
		normalizedFileName,
		extension,
		uploadType,
		bufferedSource,
		false,
		"",
	)
}

// Remove deletes one file only when it resolves inside the
// configured media storage root.
func (m *AssetFileManager) Remove(
	storagePath string,
) error {
	if m == nil {
		return ErrManagedMediaPathRequired
	}

	if err := m.validateManagedPath(
		storagePath,
	); err != nil {
		return err
	}

	err := os.Remove(
		filepath.Clean(storagePath),
	)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf(
			"remove managed media file: %w",
			err,
		)
	}

	return nil
}

func (m *AssetFileManager) validateManagedPath(
	pathValue string,
) error {
	if m == nil ||
		strings.TrimSpace(m.rootPath) == "" ||
		strings.TrimSpace(pathValue) == "" {
		return ErrManagedMediaPathRequired
	}

	absolutePath, err := filepath.Abs(
		pathValue,
	)
	if err != nil {
		return ErrManagedMediaPathRequired
	}
	absolutePath = filepath.Clean(
		absolutePath,
	)

	relativePath, err := filepath.Rel(
		m.rootPath,
		absolutePath,
	)
	if err != nil ||
		relativePath == "." ||
		relativePath == ".." ||
		strings.HasPrefix(
			relativePath,
			".."+string(os.PathSeparator),
		) ||
		filepath.IsAbs(relativePath) {
		return ErrManagedMediaPathRequired
	}

	return nil
}

func (m *AssetFileManager) ensureManagedDirectory(
	directoryPath string,
) error {
	if err := m.validateManagedPath(
		directoryPath,
	); err != nil {
		return err
	}

	if err := os.MkdirAll(
		directoryPath,
		0o700,
	); err != nil {
		return err
	}

	relativePath, err := filepath.Rel(
		m.rootPath,
		filepath.Clean(directoryPath),
	)
	if err != nil {
		return ErrManagedMediaPathRequired
	}

	currentPath := m.rootPath
	for _, pathPart := range strings.Split(
		relativePath,
		string(os.PathSeparator),
	) {
		if pathPart == "" ||
			pathPart == "." {
			continue
		}

		currentPath = filepath.Join(
			currentPath,
			pathPart,
		)
		information, inspectErr := os.Lstat(
			currentPath,
		)
		if inspectErr != nil {
			return inspectErr
		}
		if !information.IsDir() ||
			information.Mode()&
				os.ModeSymlink != 0 {
			return ErrManagedMediaPathRequired
		}
	}

	return nil
}

func normalizeMediaUploadName(
	originalFileName string,
) (
	string,
	string,
	mediaUploadType,
	error,
) {
	originalFileName = strings.TrimSpace(
		originalFileName,
	)
	originalFileName = strings.ReplaceAll(
		originalFileName,
		"\\",
		"/",
	)
	originalFileName = filepath.Base(
		originalFileName,
	)

	if originalFileName == "" ||
		originalFileName == "." ||
		len(originalFileName) > 255 {
		return "", "", mediaUploadType{},
			ErrInvalidMediaUpload
	}

	for _, character := range originalFileName {
		if unicode.IsControl(character) {
			return "", "", mediaUploadType{},
				ErrInvalidMediaUpload
		}
	}

	extension := strings.ToLower(
		filepath.Ext(originalFileName),
	)
	uploadType, supported :=
		supportedMediaUploadTypes[extension]
	if !supported {
		return "", "", mediaUploadType{},
			ErrUnsupportedMediaUpload
	}

	return originalFileName,
		extension,
		uploadType,
		nil
}

func validateMediaUploadMimeType(
	extension string,
	uploadType mediaUploadType,
	declaredMimeType string,
	detectedMimeType string,
	header []byte,
) error {
	declaredMimeType = normalizeMimeType(
		declaredMimeType,
	)
	detectedMimeType = normalizeMimeType(
		detectedMimeType,
	)

	if declaredMimeType != "" &&
		declaredMimeType !=
			"application/octet-stream" &&
		!mimeTypeMatchesMedia(
			uploadType,
			declaredMimeType,
		) {
		return fmt.Errorf(
			"%w: declared MIME type does not match extension",
			ErrUnsupportedMediaUpload,
		)
	}

	if detectedMimeType != "" &&
		detectedMimeType !=
			"application/octet-stream" &&
		!mimeTypeMatchesMedia(
			uploadType,
			detectedMimeType,
		) {
		return fmt.Errorf(
			"%w: detected MIME type does not match extension",
			ErrUnsupportedMediaUpload,
		)
	}

	if uploadType.MediaType ==
		MediaTypeDocument &&
		!strings.HasPrefix(
			string(header),
			"%PDF-",
		) {
		return fmt.Errorf(
			"%w: document is not a valid PDF",
			ErrUnsupportedMediaUpload,
		)
	}

	if !matchesExpectedMediaSignature(
		extension,
		header,
	) {
		return fmt.Errorf(
			"%w: file signature does not match extension",
			ErrUnsupportedMediaUpload,
		)
	}

	return nil
}

func normalizeMimeType(
	value string,
) string {
	value = strings.TrimSpace(
		value,
	)
	if value == "" {
		return ""
	}

	parsedType, _, err := mime.ParseMediaType(
		value,
	)
	if err != nil {
		return strings.ToLower(value)
	}

	return strings.ToLower(
		strings.TrimSpace(parsedType),
	)
}

func mimeTypeMatchesMedia(
	uploadType mediaUploadType,
	mimeType string,
) bool {
	mimeType = strings.ToLower(
		strings.TrimSpace(mimeType),
	)

	switch uploadType.MediaType {
	case MediaTypeImage:
		return strings.HasPrefix(
			mimeType,
			"image/",
		)

	case MediaTypeVideo:
		return strings.HasPrefix(
			mimeType,
			"video/",
		)

	case MediaTypeAudio:
		return strings.HasPrefix(
			mimeType,
			"audio/",
		) ||
			mimeType == "application/ogg"

	case MediaTypeDocument:
		return mimeType == "application/pdf"

	default:
		return false
	}
}

type mediaContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *mediaContextReader) Read(
	buffer []byte,
) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()

	default:
		return r.reader.Read(buffer)
	}
}
