package deepfakeforensics

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
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

	"github.com/google/uuid"
)

const (
	mediaEncryptedHeader    = "DDHMFv1\x00"
	mediaAuthenticationSize = sha256.Size
)

// PreparedMediaSource is a verified plaintext view used
// only for the lifetime of one analysis call.
type PreparedMediaSource struct {
	Path    string
	Cleanup func() error
}

func (m *AssetFileManager) persistMediaStream(
	ctx context.Context,
	organizationID uuid.UUID,
	originalFileName string,
	extension string,
	uploadType mediaUploadType,
	source io.Reader,
	quarantined bool,
	quarantineReason string,
) (*StoredMediaFile, error) {
	if m == nil ||
		ctx == nil ||
		organizationID == uuid.Nil ||
		source == nil {
		return nil, ErrInvalidMediaUpload
	}

	baseDirectory := m.rootPath
	status := mediaAssetStatusAvailable
	if quarantined {
		baseDirectory = m.quarantinePath
		status = mediaAssetStatusQuarantined
	}

	organizationDirectory := filepath.Join(
		baseDirectory,
		organizationID.String(),
		time.Now().UTC().Format("20060102"),
	)
	if err := m.ensureManagedDirectory(
		organizationDirectory,
	); err != nil {
		return nil, fmt.Errorf(
			"create organization media directory: %w",
			err,
		)
	}

	storageID := uuid.New()
	storedFileName := storageID.String() + extension
	if quarantined {
		storedFileName += ".quarantine"
	}
	if m.encryptionEnabled {
		storedFileName += ".ddh"
	}

	finalPath := filepath.Join(
		organizationDirectory,
		storedFileName,
	)
	temporaryPath := filepath.Join(
		organizationDirectory,
		".upload-"+storageID.String()+".tmp",
	)
	if err := m.validateManagedPath(
		finalPath,
	); err != nil {
		return nil, err
	}
	if err := m.validateManagedPath(
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

	plaintextHasher := sha256.New()
	destination := io.Writer(output)
	var authentication hashFinalizer

	if m.encryptionEnabled {
		destination, authentication, err =
			m.encryptedDestination(output)
		if err != nil {
			return nil, err
		}
	}

	limitedSource := io.LimitReader(
		&mediaContextReader{
			ctx:    ctx,
			reader: source,
		},
		m.maximumBytes+1,
	)

	writtenBytes, copyErr := io.CopyBuffer(
		io.MultiWriter(
			destination,
			plaintextHasher,
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

	if authentication != nil {
		if _, err = output.Write(
			authentication.Sum(nil),
		); err != nil {
			return nil, fmt.Errorf(
				"write media authentication tag: %w",
				err,
			)
		}
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

	var encryptionAlgorithm *string
	if m.encryptionEnabled {
		algorithm := mediaStorageEncryptionAlgorithm
		encryptionAlgorithm = &algorithm
	}

	return &StoredMediaFile{
		OriginalFileName: originalFileName,
		StoredFileName:   storedFileName,
		StoragePath:      finalPath,

		MediaType:     uploadType.MediaType,
		MimeType:      uploadType.MimeType,
		FileExtension: extension,

		FileSizeBytes: writtenBytes,
		FileHash: hex.EncodeToString(
			plaintextHasher.Sum(nil),
		),

		IsEncrypted:         m.encryptionEnabled,
		EncryptionAlgorithm: encryptionAlgorithm,
		Status:              status,
		QuarantineReason: strings.TrimSpace(
			quarantineReason,
		),
	}, nil
}

// PrepareAnalysisSource validates a stored asset and
// decrypts it to a short-lived job directory when needed.
func (m *AssetFileManager) PrepareAnalysisSource(
	ctx context.Context,
	asset MediaAnalysisAsset,
	jobID uuid.UUID,
) (*PreparedMediaSource, error) {
	if m == nil ||
		ctx == nil ||
		asset.ID == uuid.Nil ||
		asset.OrganizationID == uuid.Nil ||
		jobID == uuid.Nil {
		return nil, ErrInvalidMediaUpload
	}

	if err := m.inspectManagedFile(
		asset.StoragePath,
	); err != nil {
		return nil, err
	}

	if !asset.IsEncrypted {
		if err := verifyPlainMediaFile(
			ctx,
			asset.StoragePath,
			asset.FileExtension,
			asset.FileSizeBytes,
			asset.FileHash,
		); err != nil {
			return nil, err
		}

		return &PreparedMediaSource{
			Path: asset.StoragePath,
			Cleanup: func() error {
				return nil
			},
		}, nil
	}

	if len(m.encryptionKey) != 32 {
		return nil, fmt.Errorf(
			"%w: encrypted asset key is unavailable",
			ErrMediaStorageIntegrity,
		)
	}
	if asset.EncryptionAlgorithm == nil ||
		NormalizeConstant(
			*asset.EncryptionAlgorithm,
		) !=
			NormalizeConstant(
				mediaStorageEncryptionAlgorithm,
			) {
		return nil, fmt.Errorf(
			"%w: unsupported storage encryption algorithm",
			ErrMediaStorageIntegrity,
		)
	}

	jobDirectory := filepath.Join(
		m.runtimePath,
		asset.OrganizationID.String(),
		jobID.String(),
	)
	if err := m.ensureManagedDirectory(
		jobDirectory,
	); err != nil {
		return nil, err
	}

	extension := ""
	if asset.FileExtension != nil {
		extension = strings.ToLower(
			strings.TrimSpace(
				*asset.FileExtension,
			),
		)
	}
	plaintextPath := filepath.Join(
		jobDirectory,
		uuid.NewString()+extension,
	)

	if err := m.decryptStoredFile(
		ctx,
		asset.StoragePath,
		plaintextPath,
		asset.FileSizeBytes,
		asset.FileHash,
		extension,
	); err != nil {
		_ = os.RemoveAll(jobDirectory)
		return nil, err
	}

	return &PreparedMediaSource{
		Path: plaintextPath,
		Cleanup: func() error {
			return m.removeRuntimeDirectory(
				jobDirectory,
			)
		},
	}, nil
}

// ValidateStoredAsset performs the same integrity checks
// used before analysis without retaining plaintext.
func (m *AssetFileManager) ValidateStoredAsset(
	ctx context.Context,
	asset MediaAnalysisAsset,
) error {
	prepared, err := m.PrepareAnalysisSource(
		ctx,
		asset,
		uuid.New(),
	)
	if err != nil {
		return err
	}
	if prepared.Cleanup != nil {
		return prepared.Cleanup()
	}
	return nil
}

// CleanupTemporaryFiles removes only expired verified
// plaintext staging files under the dedicated runtime root.
func (m *AssetFileManager) CleanupTemporaryFiles(
	cutoff time.Time,
) (int64, error) {
	if m == nil ||
		cutoff.IsZero() {
		return 0, ErrManagedMediaPathRequired
	}

	var removed int64
	err := filepath.WalkDir(
		m.runtimePath,
		func(
			path string,
			entry os.DirEntry,
			walkErr error,
		) error {
			if walkErr != nil {
				return walkErr
			}
			if path == m.runtimePath ||
				entry.IsDir() {
				return nil
			}

			information, inspectErr :=
				entry.Info()
			if inspectErr != nil {
				return inspectErr
			}
			if information.Mode()&
				os.ModeSymlink != 0 ||
				!information.Mode().IsRegular() {
				return nil
			}
			if information.ModTime().
				After(cutoff) {
				return nil
			}
			if removeErr := os.Remove(path); removeErr != nil &&
				!errors.Is(
					removeErr,
					os.ErrNotExist,
				) {
				return removeErr
			}
			removed++
			return nil
		},
	)
	if err != nil {
		return removed, fmt.Errorf(
			"cleanup temporary media files: %w",
			err,
		)
	}

	return removed, nil
}

func (m *AssetFileManager) encryptedDestination(
	output *os.File,
) (io.Writer, hashFinalizer, error) {
	encryptionKey, authenticationKey :=
		deriveMediaStorageKeys(
			m.encryptionKey,
		)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"initialize media encryption: %w",
			err,
		)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(
		rand.Reader,
		iv,
	); err != nil {
		return nil, nil, fmt.Errorf(
			"generate media encryption IV: %w",
			err,
		)
	}

	prefix := append(
		[]byte(mediaEncryptedHeader),
		iv...,
	)
	authentication :=
		hmac.New(
			sha256.New,
			authenticationKey,
		)
	if _, err = authentication.Write(
		prefix,
	); err != nil {
		return nil, nil, err
	}
	if _, err = output.Write(prefix); err != nil {
		return nil, nil, fmt.Errorf(
			"write encrypted media header: %w",
			err,
		)
	}

	ciphertextDestination := io.MultiWriter(
		output,
		authentication,
	)

	return &cipher.StreamWriter{
			S: cipher.NewCTR(block, iv),
			W: ciphertextDestination,
		},
		authentication,
		nil
}

func (m *AssetFileManager) decryptStoredFile(
	ctx context.Context,
	encryptedPath string,
	plaintextPath string,
	expectedSize int64,
	expectedHash string,
	extension string,
) error {
	input, err := os.Open(encryptedPath)
	if err != nil {
		return fmt.Errorf(
			"%w: open encrypted media: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}
	defer input.Close()

	information, err := input.Stat()
	if err != nil {
		return fmt.Errorf(
			"%w: inspect encrypted media: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}

	prefixSize := int64(
		len(mediaEncryptedHeader) +
			aes.BlockSize,
	)
	ciphertextSize :=
		information.Size() -
			prefixSize -
			mediaAuthenticationSize
	if ciphertextSize <= 0 {
		return fmt.Errorf(
			"%w: encrypted media is truncated",
			ErrMediaStorageIntegrity,
		)
	}

	prefix := make([]byte, prefixSize)
	if _, err = io.ReadFull(input, prefix); err != nil ||
		string(
			prefix[:len(mediaEncryptedHeader)],
		) != mediaEncryptedHeader {
		return fmt.Errorf(
			"%w: encrypted media header is invalid",
			ErrMediaStorageIntegrity,
		)
	}

	_, authenticationKey :=
		deriveMediaStorageKeys(
			m.encryptionKey,
		)
	authentication :=
		hmac.New(
			sha256.New,
			authenticationKey,
		)
	_, _ = authentication.Write(prefix)
	if _, err = io.CopyBuffer(
		authentication,
		io.LimitReader(
			&mediaContextReader{
				ctx:    ctx,
				reader: input,
			},
			ciphertextSize,
		),
		make([]byte, mediaUploadBufferSize),
	); err != nil {
		return fmt.Errorf(
			"%w: authenticate encrypted media: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}

	storedAuthentication :=
		make([]byte, mediaAuthenticationSize)
	if _, err = io.ReadFull(
		input,
		storedAuthentication,
	); err != nil ||
		!hmac.Equal(
			authentication.Sum(nil),
			storedAuthentication,
		) {
		return fmt.Errorf(
			"%w: encrypted media authentication failed",
			ErrMediaStorageIntegrity,
		)
	}

	if _, err = input.Seek(
		prefixSize,
		io.SeekStart,
	); err != nil {
		return fmt.Errorf(
			"%w: seek encrypted media: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}

	encryptionKey, _ :=
		deriveMediaStorageKeys(
			m.encryptionKey,
		)
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return fmt.Errorf(
			"%w: initialize media decryption: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}

	output, err := os.OpenFile(
		plaintextPath,
		os.O_WRONLY|
			os.O_CREATE|
			os.O_EXCL,
		0o600,
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary plaintext media: %w",
			err,
		)
	}

	outputExists := true
	defer func() {
		_ = output.Close()
		if outputExists {
			_ = os.Remove(plaintextPath)
		}
	}()

	iv := prefix[len(mediaEncryptedHeader):]
	plaintextHasher := sha256.New()
	written, err := io.CopyBuffer(
		io.MultiWriter(
			output,
			plaintextHasher,
		),
		&cipher.StreamReader{
			S: cipher.NewCTR(block, iv),
			R: io.LimitReader(
				&mediaContextReader{
					ctx:    ctx,
					reader: input,
				},
				ciphertextSize,
			),
		},
		make([]byte, mediaUploadBufferSize),
	)
	if err != nil {
		return fmt.Errorf(
			"%w: decrypt media: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}
	if written != expectedSize ||
		!constantTimeHashEqual(
			hex.EncodeToString(
				plaintextHasher.Sum(nil),
			),
			expectedHash,
		) {
		return fmt.Errorf(
			"%w: decrypted media hash or size mismatch",
			ErrMediaStorageIntegrity,
		)
	}

	if err = output.Sync(); err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}

	if err = verifyMediaFileSignature(
		plaintextPath,
		extension,
	); err != nil {
		return err
	}

	outputExists = false
	return nil
}

func verifyPlainMediaFile(
	ctx context.Context,
	path string,
	extension *string,
	expectedSize int64,
	expectedHash string,
) error {
	input, err := os.Open(path)
	if err != nil {
		return fmt.Errorf(
			"%w: open media: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}
	defer input.Close()

	hasher := sha256.New()
	size, err := io.CopyBuffer(
		hasher,
		&mediaContextReader{
			ctx:    ctx,
			reader: input,
		},
		make([]byte, mediaUploadBufferSize),
	)
	if err != nil {
		return fmt.Errorf(
			"%w: verify media: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}
	if size != expectedSize ||
		!constantTimeHashEqual(
			hex.EncodeToString(
				hasher.Sum(nil),
			),
			expectedHash,
		) {
		return fmt.Errorf(
			"%w: media hash or size mismatch",
			ErrMediaStorageIntegrity,
		)
	}

	extensionValue := ""
	if extension != nil {
		extensionValue = *extension
	}
	return verifyMediaFileSignature(
		path,
		extensionValue,
	)
}

func verifyMediaFileSignature(
	path string,
	extension string,
) error {
	input, err := os.Open(path)
	if err != nil {
		return fmt.Errorf(
			"%w: open media signature: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}
	defer input.Close()

	header := make([]byte, 512)
	count, err := input.Read(header)
	if err != nil &&
		!errors.Is(err, io.EOF) {
		return fmt.Errorf(
			"%w: read media signature: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}
	if count == 0 ||
		!matchesExpectedMediaSignature(
			extension,
			header[:count],
		) {
		return fmt.Errorf(
			"%w: stored media signature is invalid",
			ErrMediaStorageIntegrity,
		)
	}

	return nil
}

func (m *AssetFileManager) inspectManagedFile(
	path string,
) error {
	if err := m.validateManagedPath(path); err != nil {
		return err
	}

	information, err := os.Lstat(
		filepath.Clean(path),
	)
	if err != nil {
		return fmt.Errorf(
			"%w: inspect media file: %v",
			ErrMediaStorageIntegrity,
			err,
		)
	}
	if information.Mode()&
		os.ModeSymlink != 0 ||
		!information.Mode().IsRegular() {
		return fmt.Errorf(
			"%w: media storage path is not a regular file",
			ErrMediaStorageIntegrity,
		)
	}

	return nil
}

func (m *AssetFileManager) removeRuntimeDirectory(
	path string,
) error {
	if err := m.validateManagedPath(path); err != nil {
		return err
	}
	relative, err := filepath.Rel(
		m.runtimePath,
		filepath.Clean(path),
	)
	if err != nil ||
		relative == "." ||
		relative == ".." ||
		strings.HasPrefix(
			relative,
			".."+string(os.PathSeparator),
		) {
		return ErrManagedMediaPathRequired
	}
	if err = os.RemoveAll(path); err != nil {
		return fmt.Errorf(
			"remove temporary media directory: %w",
			err,
		)
	}
	return nil
}

func deriveMediaStorageKeys(
	masterKey []byte,
) ([]byte, []byte) {
	derive := func(label string) []byte {
		mac := hmac.New(
			sha256.New,
			masterKey,
		)
		_, _ = mac.Write([]byte(label))
		return mac.Sum(nil)
	}

	return derive("DDH_MEDIA_ENCRYPTION_V1"),
		derive("DDH_MEDIA_AUTHENTICATION_V1")
}

func constantTimeHashEqual(
	left string,
	right string,
) bool {
	left = strings.ToLower(
		strings.TrimSpace(left),
	)
	right = strings.ToLower(
		strings.TrimSpace(right),
	)
	if len(left) != len(right) {
		return false
	}

	return subtle.ConstantTimeCompare(
		[]byte(left),
		[]byte(right),
	) == 1
}

type hashFinalizer interface {
	io.Writer
	Sum([]byte) []byte
}
