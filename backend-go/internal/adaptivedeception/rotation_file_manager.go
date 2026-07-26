package adaptivedeception

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var dynamicCanaryRotationSuffixPattern = regexp.MustCompile(
	`(?i)(?:_ROT_[0-9]{8}T[0-9]{6}_[0-9A-F]{8})+$`,
)

// PreservedCanaryEvidence identifies the forensic copy
// retained before an existing canary is rotated.
type PreservedCanaryEvidence struct {
	Exists       bool
	OriginalPath string
	EvidencePath string
}

// RotationDestination contains the controlled dynamic
// filename and deployment path for a rotated canary.
type RotationDestination struct {
	FileName string
	FilePath string
}

// RotationFileManager performs filesystem operations only
// inside the configured canary deployment root.
type RotationFileManager struct {
	deploymentRoot string
	evidenceRoot   string
}

func NewRotationFileManager(
	deploymentRoot string,
) (*RotationFileManager, error) {
	deploymentRoot =
		strings.TrimSpace(
			deploymentRoot,
		)

	if deploymentRoot == "" {
		return nil, errors.New(
			"canary deployment root is required",
		)
	}

	absoluteRoot, err :=
		filepath.Abs(deploymentRoot)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve canary deployment root: %w",
			err,
		)
	}

	absoluteRoot =
		filepath.Clean(
			absoluteRoot,
		)

	evidenceRoot :=
		filepath.Join(
			absoluteRoot,
			".adaptive-evidence",
		)

	if err = os.MkdirAll(
		absoluteRoot,
		0750,
	); err != nil {
		return nil, fmt.Errorf(
			"create canary deployment root: %w",
			err,
		)
	}

	if err = os.MkdirAll(
		evidenceRoot,
		0750,
	); err != nil {
		return nil, fmt.Errorf(
			"create adaptive evidence root: %w",
			err,
		)
	}

	return &RotationFileManager{
		deploymentRoot: absoluteRoot,
		evidenceRoot:   evidenceRoot,
	}, nil
}

func (m *RotationFileManager) PreserveEvidence(
	ctx context.Context,
	snapshot *CanaryFileSnapshot,
	rotationID uuid.UUID,
) (*PreservedCanaryEvidence, error) {
	if m == nil {
		return nil, errors.New(
			"rotation file manager is unavailable",
		)
	}

	if snapshot == nil {
		return nil, errors.New(
			"canary file snapshot is required",
		)
	}

	if rotationID == uuid.Nil {
		return nil, errors.New(
			"rotation ID is required",
		)
	}

	originalPath, err :=
		m.validateManagedPath(
			snapshot.FilePath,
		)
	if err != nil {
		return nil, err
	}

	evidence := &PreservedCanaryEvidence{
		OriginalPath: originalPath,
	}

	fileInfo, err := os.Stat(
		originalPath,
	)
	if err != nil {
		if errors.Is(
			err,
			os.ErrNotExist,
		) {
			return evidence, nil
		}

		return nil, fmt.Errorf(
			"inspect canary before evidence preservation: %w",
			err,
		)
	}

	if fileInfo.IsDir() {
		return nil, errors.New(
			"canary file path points to a directory",
		)
	}

	evidenceDirectory :=
		filepath.Join(
			m.evidenceRoot,
			snapshot.OrganizationID.String(),
			snapshot.ID.String(),
			rotationID.String(),
		)

	if err = os.MkdirAll(
		evidenceDirectory,
		0750,
	); err != nil {
		return nil, fmt.Errorf(
			"create canary evidence directory: %w",
			err,
		)
	}

	evidenceFileName :=
		snapshot.FileName +
			".evidence"

	evidencePath :=
		filepath.Join(
			evidenceDirectory,
			evidenceFileName,
		)

	if err = copyFileWithContext(
		ctx,
		originalPath,
		evidencePath,
	); err != nil {
		return nil, fmt.Errorf(
			"preserve canary evidence: %w",
			err,
		)
	}

	evidence.Exists = true
	evidence.EvidencePath =
		evidencePath

	return evidence, nil
}

func (m *RotationFileManager) ResolveDestination(
	snapshot *CanaryFileSnapshot,
	rotationID uuid.UUID,
	strategy string,
	requestedFileName string,
	now time.Time,
) (*RotationDestination, error) {
	if m == nil {
		return nil, errors.New(
			"rotation file manager is unavailable",
		)
	}

	if snapshot == nil {
		return nil, errors.New(
			"canary file snapshot is required",
		)
	}

	if rotationID == uuid.Nil {
		return nil, errors.New(
			"rotation ID is required",
		)
	}

	strategy =
		NormalizeConstant(strategy)

	if !IsSupportedRotationStrategy(
		strategy,
	) {
		return nil, errors.New(
			"unsupported canary rotation strategy",
		)
	}

	currentPath, err :=
		m.validateManagedPath(
			snapshot.FilePath,
		)
	if err != nil {
		return nil, err
	}

	currentDirectory :=
		filepath.Dir(currentPath)

	fileName :=
		strings.TrimSpace(
			requestedFileName,
		)

	if fileName != "" {
		if filepath.Base(fileName) !=
			fileName {
			return nil, errors.New(
				"rotated canary filename cannot contain a directory path",
			)
		}
	}

	requiresDynamicName :=
		strategy ==
			RotationStrategyRename ||
			strategy ==
				RotationStrategyRegenerateAndRelocate

	if fileName == "" {
		if requiresDynamicName {
			fileName =
				buildDynamicCanaryFileName(
					snapshot.FileName,
					rotationID,
					now,
				)
		} else {
			fileName =
				snapshot.FileName
		}
	}

	targetDirectory :=
		currentDirectory

	if strategy ==
		RotationStrategyRelocate ||
		strategy ==
			RotationStrategyRegenerateAndRelocate {
		targetDirectory =
			filepath.Join(
				m.deploymentRoot,
				"adaptive-rotations",
				snapshot.OrganizationID.String(),
				snapshot.ID.String(),
				now.UTC().Format(
					"20060102T150405.000000000",
				),
			)
	}

	if err = os.MkdirAll(
		targetDirectory,
		0750,
	); err != nil {
		return nil, fmt.Errorf(
			"create rotated canary directory: %w",
			err,
		)
	}

	targetPath :=
		filepath.Join(
			targetDirectory,
			fileName,
		)

	targetPath, err =
		m.validateManagedPath(
			targetPath,
		)
	if err != nil {
		return nil, err
	}

	return &RotationDestination{
		FileName: fileName,
		FilePath: targetPath,
	}, nil
}

func (m *RotationFileManager) DeployGeneratedFile(
	ctx context.Context,
	sourcePath string,
	destinationPath string,
) error {
	if m == nil {
		return errors.New(
			"rotation file manager is unavailable",
		)
	}

	destinationPath, err :=
		m.validateManagedPath(
			destinationPath,
		)
	if err != nil {
		return err
	}

	sourcePath =
		filepath.Clean(
			strings.TrimSpace(
				sourcePath,
			),
		)

	if sourcePath == "" {
		return errors.New(
			"generated canary source path is required",
		)
	}

	if err = os.MkdirAll(
		filepath.Dir(destinationPath),
		0750,
	); err != nil {
		return fmt.Errorf(
			"create rotated canary destination directory: %w",
			err,
		)
	}

	temporaryPath :=
		destinationPath +
			"." +
			uuid.NewString() +
			".tmp"

	if err = copyFileWithContext(
		ctx,
		sourcePath,
		temporaryPath,
	); err != nil {
		return err
	}

	cleanupTemporary := true

	defer func() {
		if cleanupTemporary {
			_ = os.Remove(
				temporaryPath,
			)
		}
	}()

	_, destinationErr :=
		os.Stat(destinationPath)

	if errors.Is(
		destinationErr,
		os.ErrNotExist,
	) {
		if err = os.Rename(
			temporaryPath,
			destinationPath,
		); err != nil {
			return fmt.Errorf(
				"activate rotated canary file: %w",
				err,
			)
		}

		cleanupTemporary = false
		return nil
	}

	if destinationErr != nil {
		return fmt.Errorf(
			"inspect rotated canary destination: %w",
			destinationErr,
		)
	}

	backupPath :=
		destinationPath +
			"." +
			uuid.NewString() +
			".backup"

	if err = os.Rename(
		destinationPath,
		backupPath,
	); err != nil {
		return fmt.Errorf(
			"preserve current canary during atomic replacement: %w",
			err,
		)
	}

	if err = os.Rename(
		temporaryPath,
		destinationPath,
	); err != nil {
		restoreErr := os.Rename(
			backupPath,
			destinationPath,
		)

		if restoreErr != nil {
			return fmt.Errorf(
				"activate rotated canary: %v; restore previous canary: %w",
				err,
				restoreErr,
			)
		}

		return fmt.Errorf(
			"activate rotated canary file: %w",
			err,
		)
	}

	cleanupTemporary = false

	if err = os.Remove(
		backupPath,
	); err != nil &&
		!errors.Is(
			err,
			os.ErrNotExist,
		) {
		return fmt.Errorf(
			"remove temporary canary backup: %w",
			err,
		)
	}

	return nil
}

func (m *RotationFileManager) RestoreEvidence(
	ctx context.Context,
	evidence *PreservedCanaryEvidence,
	destinationPath string,
) error {
	if evidence == nil ||
		!evidence.Exists {
		return nil
	}

	return m.DeployGeneratedFile(
		ctx,
		evidence.EvidencePath,
		destinationPath,
	)
}

func (m *RotationFileManager) RemoveManagedFile(
	filePath string,
) error {
	if m == nil {
		return errors.New(
			"rotation file manager is unavailable",
		)
	}

	managedPath, err :=
		m.validateManagedPath(
			filePath,
		)
	if err != nil {
		return err
	}

	if managedPath ==
		m.deploymentRoot {
		return errors.New(
			"deployment root cannot be removed",
		)
	}

	fileInfo, err :=
		os.Stat(managedPath)
	if err != nil {
		if errors.Is(
			err,
			os.ErrNotExist,
		) {
			return nil
		}

		return err
	}

	if fileInfo.IsDir() {
		return errors.New(
			"managed path is a directory",
		)
	}

	if err = os.Remove(
		managedPath,
	); err != nil &&
		!errors.Is(
			err,
			os.ErrNotExist,
		) {
		return fmt.Errorf(
			"remove managed canary file: %w",
			err,
		)
	}

	return nil
}

func (m *RotationFileManager) validateManagedPath(
	filePath string,
) (string, error) {
	filePath =
		strings.TrimSpace(
			filePath,
		)

	if filePath == "" {
		return "", errors.New(
			"canary file path is required",
		)
	}

	absolutePath, err :=
		filepath.Abs(filePath)
	if err != nil {
		return "", err
	}

	absolutePath =
		filepath.Clean(
			absolutePath,
		)

	relativePath, err :=
		filepath.Rel(
			m.deploymentRoot,
			absolutePath,
		)
	if err != nil {
		return "", err
	}

	if relativePath == "." ||
		relativePath == ".." ||
		strings.HasPrefix(
			relativePath,
			".."+string(os.PathSeparator),
		) ||
		filepath.IsAbs(relativePath) {
		return "", errors.New(
			"canary path is outside the configured deployment root",
		)
	}

	return absolutePath, nil
}

func buildDynamicCanaryFileName(
	currentFileName string,
	rotationID uuid.UUID,
	now time.Time,
) string {
	currentFileName =
		filepath.Base(
			strings.TrimSpace(
				currentFileName,
			),
		)

	extension :=
		filepath.Ext(
			currentFileName,
		)

	baseName :=
		strings.TrimSuffix(
			currentFileName,
			extension,
		)

	// Remove every previous adaptive rotation suffix.
	// This prevents repeated rotations from producing
	// continuously growing filenames.
	baseName =
		dynamicCanaryRotationSuffixPattern.
			ReplaceAllString(
				baseName,
				"",
			)

	baseName =
		strings.Trim(
			strings.TrimSpace(baseName),
			"_.- ",
		)

	if baseName == "" {
		baseName = "Adaptive_Canary"
	}

	// Keep dynamic paths portable for Windows tools that
	// still apply the traditional MAX_PATH limitation.
	const maximumDynamicBaseRunes = 32

	baseRunes := []rune(baseName)
	if len(baseRunes) >
		maximumDynamicBaseRunes {
		baseName = string(
			baseRunes[:maximumDynamicBaseRunes],
		)
	}
	rotationReference :=
		strings.ToUpper(
			rotationID.String()[:8],
		)

	return fmt.Sprintf(
		"%s_ROT_%s_%s%s",
		baseName,
		now.UTC().Format(
			"20060102T150405",
		),
		rotationReference,
		extension,
	)
}

func copyFileWithContext(
	ctx context.Context,
	sourcePath string,
	destinationPath string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	source, err :=
		os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf(
			"open source file: %w",
			err,
		)
	}
	defer source.Close()

	sourceInfo, err := source.Stat()
	if err != nil {
		return fmt.Errorf(
			"inspect source file: %w",
			err,
		)
	}

	if sourceInfo.IsDir() {
		return errors.New(
			"source path is a directory",
		)
	}

	destination, err :=
		os.OpenFile(
			destinationPath,
			os.O_CREATE|
				os.O_WRONLY|
				os.O_TRUNC,
			0600,
		)
	if err != nil {
		return fmt.Errorf(
			"create destination file: %w",
			err,
		)
	}

	copySucceeded := false

	defer func() {
		_ = destination.Close()

		if !copySucceeded {
			_ = os.Remove(
				destinationPath,
			)
		}
	}()

	buffer := make(
		[]byte,
		64*1024,
	)

	for {
		if err = ctx.Err(); err != nil {
			return err
		}

		bytesRead, readErr :=
			source.Read(buffer)

		if bytesRead > 0 {
			if _, err = destination.Write(
				buffer[:bytesRead],
			); err != nil {
				return fmt.Errorf(
					"write destination file: %w",
					err,
				)
			}
		}

		if errors.Is(
			readErr,
			io.EOF,
		) {
			break
		}

		if readErr != nil {
			return fmt.Errorf(
				"read source file: %w",
				readErr,
			)
		}
	}

	if err = destination.Sync(); err != nil {
		return fmt.Errorf(
			"synchronize destination file: %w",
			err,
		)
	}

	if err = destination.Close(); err != nil {
		return fmt.Errorf(
			"close destination file: %w",
			err,
		)
	}

	copySucceeded = true

	return nil
}
