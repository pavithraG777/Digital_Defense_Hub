package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	refreshTokenByteLength = 64
	refreshTokenDuration   = 7 * 24 * time.Hour
)

type GeneratedRefreshToken struct {
	ID        uuid.UUID
	Token     string
	ExpiresAt time.Time
}

// GenerateRefreshToken creates a cryptographically secure refresh token.
//
// The raw token is returned to the client, while refresh_repository.go
// stores only the SHA-256 hash of this token in the database.
func GenerateRefreshToken() (*GeneratedRefreshToken, error) {
	randomBytes := make(
		[]byte,
		refreshTokenByteLength,
	)

	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf(
			"failed to generate secure refresh token: %w",
			err,
		)
	}

	rawToken := base64.RawURLEncoding.EncodeToString(
		randomBytes,
	)

	now := time.Now().UTC()

	return &GeneratedRefreshToken{
		ID:        uuid.New(),
		Token:     rawToken,
		ExpiresAt: now.Add(refreshTokenDuration),
	}, nil
}

// RefreshTokenDuration returns the configured refresh-token lifetime.
func RefreshTokenDuration() time.Duration {
	return refreshTokenDuration
}
