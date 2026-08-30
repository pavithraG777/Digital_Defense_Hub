package deepfakeforensics

import (
	"errors"
	"testing"
)

func TestNormalizeAllowedMediaTypes(t *testing.T) {
	actual, err := normalizeAllowedMediaTypes([]string{" image ", "VIDEO", "image"})
	if err != nil {
		t.Fatalf("normalizeAllowedMediaTypes returned error: %v", err)
	}
	if len(actual) != 2 || actual[0] != MediaTypeImage || actual[1] != MediaTypeVideo {
		t.Fatalf("unexpected normalized types: %#v", actual)
	}
}

func TestNormalizeAllowedMediaTypesRejectsUnsupportedValue(t *testing.T) {
	_, err := normalizeAllowedMediaTypes([]string{"ARCHIVE"})
	if !errors.Is(err, ErrInvalidMediaPolicy) {
		t.Fatalf("expected ErrInvalidMediaPolicy, got %v", err)
	}
}
