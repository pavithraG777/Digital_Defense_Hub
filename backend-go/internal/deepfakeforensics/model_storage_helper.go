package deepfakeforensics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func resolveModelStoragePath(storageRoot, relativePath string) (string, error) {
	storageRoot = filepath.Clean(strings.TrimSpace(storageRoot))
	if storageRoot == "" {
		storageRoot = "./storage/models"
	}
	absoluteRoot, err := filepath.Abs(storageRoot)
	if err != nil {
		return "", fmt.Errorf("resolve model storage root: %w", err)
	}
	candidate := filepath.Clean(filepath.Join(absoluteRoot, filepath.FromSlash(strings.TrimSpace(relativePath))))
	if !pathWithinRoot(absoluteRoot, candidate) {
		return "", fmt.Errorf("%w: model path is outside the managed storage root", ErrManagedMediaPathRequired)
	}
	if err = os.MkdirAll(filepath.Dir(candidate), 0o700); err != nil {
		return "", fmt.Errorf("create model storage directory: %w", err)
	}
	return candidate, nil
}
