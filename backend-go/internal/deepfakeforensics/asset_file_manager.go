package deepfakeforensics

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
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
)

type mediaUploadType struct {
	MediaType string
	MimeType  string
}

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

	FileSizeBytes int64
	FileHash      string
}

// AssetFileManager owns organization-isolated local media
// upload storage.
type AssetFileManager struct {
	rootPath     string
	maximumBytes int64
}

func NewAssetFileManager(
	rootPath string,
	maximumBytes int64,
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

	return &AssetFileManager{
		rootPath:     absoluteRoot,
		maximumBytes: maximumBytes,
	}, nil
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
		uploadType,
		declaredMimeType,
		detectedMimeType,
		header,
	); err != nil {
		return nil, err
	}

	organizationDirectory := filepath.Join(
		m.rootPath,
		organizationID.String(),
		time.Now().UTC().Format("20060102"),
	)
	if err = m.validateManagedPath(
		organizationDirectory,
	); err != nil {
		return nil, err
	}
	if err = m.ensureManagedDirectory(
		organizationDirectory,
	); err != nil {
		return nil, fmt.Errorf(
			"create organization media directory: %w",
			err,
		)
	}

	storageID := uuid.New()
	storedFileName :=
		storageID.String() + extension
	finalPath := filepath.Join(
		organizationDirectory,
		storedFileName,
	)
	temporaryPath := filepath.Join(
		organizationDirectory,
		".upload-"+storageID.String()+".tmp",
	)

	if err = m.validateManagedPath(
		finalPath,
	); err != nil {
		return nil, err
	}
	if err = m.validateManagedPath(
		temporaryPath,
	); err != nil {
		return nil, err
	}

	output, err := os.OpenFile(
		temporaryPath,
		os.O_WRONLY|
			os.O_CREATE|
			os.O_EXCL,
		0o600,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create temporary media upload: %w",
			err,
		)
	}

	temporaryFileExists := true
	defer func() {
		_ = output.Close()
		if temporaryFileExists {
			_ = os.Remove(temporaryPath)
		}
	}()

	hasher := sha256.New()
	limitedSource := io.LimitReader(
		bufferedSource,
		m.maximumBytes+1,
	)

	writtenBytes, copyErr := io.CopyBuffer(
		io.MultiWriter(
			output,
			hasher,
		),
		limitedSource,
		make(
			[]byte,
			mediaUploadBufferSize,
		),
	)
	if copyErr != nil {
		return nil, fmt.Errorf(
			"store media upload: %w",
			copyErr,
		)
	}
	if writtenBytes > m.maximumBytes {
		return nil, ErrMediaUploadTooLarge
	}
	if writtenBytes == 0 {
		return nil, fmt.Errorf(
			"%w: uploaded file is empty",
			ErrInvalidMediaUpload,
		)
	}

	if err = output.Sync(); err != nil {
		return nil, fmt.Errorf(
			"synchronize media upload: %w",
			err,
		)
	}
	if err = output.Close(); err != nil {
		return nil, fmt.Errorf(
			"close media upload: %w",
			err,
		)
	}

	if err = os.Rename(
		temporaryPath,
		finalPath,
	); err != nil {
		return nil, fmt.Errorf(
			"publish media upload: %w",
			err,
		)
	}
	temporaryFileExists = false

	return &StoredMediaFile{
		OriginalFileName: normalizedFileName,
		StoredFileName:   storedFileName,
		StoragePath:      finalPath,

		MediaType:     uploadType.MediaType,
		MimeType:      uploadType.MimeType,
		FileExtension: extension,

		FileSizeBytes: writtenBytes,
		FileHash: hex.EncodeToString(
			hasher.Sum(nil),
		),
	}, nil
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
