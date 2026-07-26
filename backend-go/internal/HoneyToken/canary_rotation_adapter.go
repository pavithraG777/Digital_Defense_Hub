package honeytoken

import (
	"context"

	"github.com/google/uuid"
)

// CanaryRotationGenerationInput contains the information
// required to regenerate an existing canary identity.
type CanaryRotationGenerationInput struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID

	FileName   string
	CanaryType string

	LinkedHoneytokenCode *string
}

// CanaryRotationGenerationResult exposes generated canary
// metadata to the Adaptive Deception module.
type CanaryRotationGenerationResult struct {
	CanaryCode string

	FileName      string
	FilePath      string
	FileExtension string
	MimeType      string

	OriginalFileHash string
	HashAlgorithm    string
	FileSizeBytes    int64

	TrackingIdentifier string
}

// GenerateForRotation regenerates canary content using the
// existing secure canary generator implementation.
func (g *CanaryGenerator) GenerateForRotation(
	ctx context.Context,
	input CanaryRotationGenerationInput,
) (*CanaryRotationGenerationResult, error) {
	result, err := g.Generate(
		ctx,
		canaryGenerationInput{
			ID: input.ID,

			OrganizationID: input.OrganizationID,

			FileName: input.FileName,

			CanaryType: input.CanaryType,

			LinkedHoneytokenCode: input.LinkedHoneytokenCode,
		},
	)
	if err != nil {
		return nil, err
	}

	return &CanaryRotationGenerationResult{
		CanaryCode: result.CanaryCode,

		FileName: result.FileName,

		FilePath: result.FilePath,

		FileExtension: result.FileExtension,

		MimeType: result.MimeType,

		OriginalFileHash: result.OriginalFileHash,

		HashAlgorithm: result.HashAlgorithm,

		FileSizeBytes: result.FileSizeBytes,

		TrackingIdentifier: result.TrackingIdentifier,
	}, nil
}

// RemoveRotationGeneratedFile safely removes a generated
// staging file when rotation or deployment fails.
func (g *CanaryGenerator) RemoveRotationGeneratedFile(
	filePath string,
) error {
	return g.RemoveGeneratedFile(
		filePath,
	)
}
